//! Trusted account lifecycle worker. One dedicated OS thread owns storage
//! and the async connector runtime; no arbitrary IPC commands or closures.
//! The independent retirement signal closes admission even during an Ask.
use super::workspace_runtime::WorkspaceRuntime;
use crate::{
    account_credentials::{AccountId, ActiveSession, Store},
    agent::{
        local_model::LocalModelProvider,
        tool_loop::{LoopAnswer, LoopError, LoopFailure},
    },
    tools::{approvals::ApprovalGate, mcp_catalog::McpPolicy},
};
use std::{
    collections::BTreeSet,
    net::SocketAddrV4,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};

const CAPACITY: usize = 4;
type Reply<T> = oneshot::Sender<Result<T, String>>;

#[derive(Clone)]
pub(crate) struct SessionSignal {
    session: ActiveSession,
    gate: Arc<ApprovalGate>,
}

impl SessionSignal {
    pub(crate) fn session(&self) -> ActiveSession {
        self.session
    }
    pub(crate) fn gate(&self) -> Arc<ApprovalGate> {
        self.gate.clone()
    }
    // Only this exact session is affected, even if the signal is retained.
    pub(crate) fn request_retirement(&self) -> Result<(), String> {
        self.gate.cancel_pending_for_shutdown().map(|_| ())
    }
}

enum Command {
    Enroll(Reply<AccountId>),
    Activate(AccountId, Reply<SessionSignal>),
    AddStdio(
        ActiveSession,
        String,
        PathBuf,
        Vec<String>,
        PathBuf,
        Reply<()>,
    ),
    AddHttp(ActiveSession, String, SocketAddrV4, Reply<()>),
    Refresh(ActiveSession, String, Reply<()>),
    Remove(ActiveSession, String, Reply<()>),
    Policy(ActiveSession, String, McpPolicy, Reply<()>),
    Run(
        ActiveSession,
        Arc<LocalModelProvider>,
        String,
        BTreeSet<String>,
        oneshot::Sender<Result<LoopAnswer, LoopFailure>>,
    ),
    Retire(ActiveSession, Reply<()>),
    Stop(Reply<()>),
}

#[derive(Default)]
struct Control {
    stopping: bool,
    stopped_cleanly: bool,
    active: Option<SessionSignal>,
}

pub(crate) struct WorkspaceWorker {
    tx: mpsc::Sender<Command>,
    signal: Arc<Mutex<Control>>,
    exited: Option<oneshot::Receiver<()>>,
}

impl WorkspaceWorker {
    pub(crate) async fn start<S: Store + Send + 'static>(
        support: PathBuf,
        store: S,
    ) -> Result<Self, String> {
        let (tx, rx) = mpsc::channel(CAPACITY);
        let (ready, opened) = oneshot::channel::<Result<(), String>>();
        let (exit, exited) = oneshot::channel();
        let signal = Arc::new(Mutex::new(Control::default()));
        let worker_signal = signal.clone();
        std::thread::Builder::new()
            .name("account-runtime".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = ready.send(Err("Workspace runtime unavailable".into()));
                        return;
                    }
                };
                let host = match WorkspaceRuntime::open(&support, store) {
                    Ok(host) => host,
                    Err(_) => {
                        let _ = ready.send(Err("Workspace storage unavailable".into()));
                        return;
                    }
                };
                if ready.send(Ok(())).is_ok() {
                    runtime.block_on(serve(host, rx, worker_signal));
                }
                drop(runtime);
                let _ = exit.send(());
            })
            .map_err(|_| "Workspace worker unavailable")?;
        opened.await.map_err(|_| "Workspace worker unavailable")??;
        Ok(Self {
            tx,
            signal,
            exited: Some(exited),
        })
    }

    fn submit(&self, command: Command) -> Result<(), String> {
        let control = self
            .signal
            .lock()
            .map_err(|_| "Workspace signal unavailable")?;
        if control.stopping && !matches!(&command, Command::Stop(_) | Command::Retire(_, _)) {
            return Err("Workspace worker stopping".into());
        }
        self.tx
            .try_send(command)
            .map_err(|_| "Workspace worker busy or unavailable".into())
    }

    pub(crate) async fn enroll(&self) -> Result<AccountId, String> {
        let (tx, rx) = oneshot::channel();
        self.submit(Command::Enroll(tx))?;
        receive(rx).await
    }
    pub(crate) async fn activate(&self, account: AccountId) -> Result<SessionSignal, String> {
        let (tx, rx) = oneshot::channel();
        self.submit(Command::Activate(account, tx))?;
        receive(rx).await
    }
    pub(crate) async fn add_stdio(
        &self,
        session: ActiveSession,
        id: String,
        executable: PathBuf,
        args: Vec<String>,
        cwd: PathBuf,
    ) -> Result<(), String> {
        if id.len() > 32
            || args.len() > 32
            || args.iter().any(|a| a.len() > 4096)
            || executable.as_os_str().len() > 4096
            || cwd.as_os_str().len() > 4096
        {
            return Err("Workspace connector configuration rejected".into());
        }
        let (tx, rx) = oneshot::channel();
        self.submit(Command::AddStdio(session, id, executable, args, cwd, tx))?;
        receive(rx).await
    }
    pub(crate) async fn add_http(
        &self,
        session: ActiveSession,
        id: String,
        address: SocketAddrV4,
    ) -> Result<(), String> {
        if id.len() > 32 {
            return Err("Workspace connector configuration rejected".into());
        }
        let (tx, rx) = oneshot::channel();
        self.submit(Command::AddHttp(session, id, address, tx))?;
        receive(rx).await
    }
    pub(crate) async fn refresh_connector(
        &self,
        session: ActiveSession,
        id: String,
    ) -> Result<(), String> {
        if !crate::tools::mcp_catalog::valid_connector(&id) {
            return Err("Workspace connector configuration rejected".into());
        }
        let (tx, rx) = oneshot::channel();
        self.submit(Command::Refresh(session, id, tx))?;
        receive(rx).await
    }

    pub(crate) async fn remove_connector(
        &self,
        session: ActiveSession,
        id: String,
    ) -> Result<(), String> {
        if !crate::tools::mcp_catalog::valid_connector(&id) {
            return Err("Workspace connector configuration rejected".into());
        }
        let (tx, rx) = oneshot::channel();
        self.submit(Command::Remove(session, id, tx))?;
        receive(rx).await
    }

    pub(crate) async fn set_policy(
        &self,
        session: ActiveSession,
        function: String,
        policy: McpPolicy,
    ) -> Result<(), String> {
        if function.len() > 64 {
            return Err("Workspace policy rejected".into());
        }
        let (tx, rx) = oneshot::channel();
        self.submit(Command::Policy(session, function, policy, tx))?;
        receive(rx).await
    }
    pub(crate) async fn run(
        &self,
        session: ActiveSession,
        provider: Arc<LocalModelProvider>,
        prompt: String,
        names: BTreeSet<String>,
    ) -> Result<LoopAnswer, LoopFailure> {
        let invalid = || LoopFailure {
            reason: LoopError::InvalidAuthority,
            confirmed_executions: 0,
        };
        if prompt.len() > 16 * 1024 || names.len() > 128 || names.iter().any(|name| name.len() > 64)
        {
            return Err(invalid());
        }
        let (tx, rx) = oneshot::channel();
        self.submit(Command::Run(session, provider, prompt, names, tx))
            .map_err(|_| invalid())?;
        rx.await.map_err(|_| invalid())?
    }
    // Close before attempting bounded queue admission. A full queue or
    // canceled receiver cannot reopen the old session; caller retries.
    pub(crate) async fn retire(&self, signal: &SessionSignal) -> Result<(), String> {
        {
            let control = self
                .signal
                .lock()
                .map_err(|_| "Workspace signal unavailable")?;
            let current = control
                .active
                .as_ref()
                .filter(|current| {
                    current.session == signal.session && Arc::ptr_eq(&current.gate, &signal.gate)
                })
                .ok_or("Workspace session unavailable")?;
            current.request_retirement()?;
        }
        let (tx, rx) = oneshot::channel();
        self.submit(Command::Retire(signal.session, tx))?;
        receive(rx).await
    }
    // Trusted readback when the activation reply was delivered but the
    // receiver was dropped before observing it. Never auto-activate again.
    pub(crate) fn current_signal(&self) -> Result<Option<SessionSignal>, String> {
        let control = self
            .signal
            .lock()
            .map_err(|_| "Workspace signal unavailable")?;
        Ok(control.active.clone())
    }

    fn stopped_cleanly(&self) -> Result<bool, String> {
        self.signal
            .lock()
            .map(|control| control.stopped_cleanly)
            .map_err(|_| "Workspace signal unavailable".into())
    }

    pub(crate) async fn stop(&mut self) -> Result<(), String> {
        close_current(&self.signal)?;
        if !self.stopped_cleanly()? {
            let (tx, rx) = oneshot::channel();
            let result = match self.submit(Command::Stop(tx)) {
                Ok(()) => receive(rx).await,
                Err(error) => Err(error),
            };
            // An earlier canceled stop may have completed while this
            // caller was submitting or waiting for its own acknowledgement.
            if !self.stopped_cleanly()? {
                result?;
                return Err("Workspace worker stop unconfirmed".into());
            }
        }
        if let Some(exit) = self.exited.as_mut() {
            exit.await
                .map_err(|_| "Workspace worker exit unconfirmed")?;
            self.exited = None;
        }
        Ok(())
    }
}

impl Drop for WorkspaceWorker {
    fn drop(&mut self) {
        let _ = close_current(&self.signal);
    }
}

fn close_current(signal: &Mutex<Control>) -> Result<(), String> {
    let mut guard = signal.lock().map_err(|_| "Workspace signal unavailable")?;
    guard.stopping = true;
    if let Some(active) = guard.active.as_ref() {
        active.request_retirement()?;
    }
    Ok(())
}
async fn receive<T>(rx: oneshot::Receiver<Result<T, String>>) -> Result<T, String> {
    rx.await.map_err(|_| "Workspace worker unavailable")?
}

async fn serve<S: Store>(
    mut host: WorkspaceRuntime<S>,
    mut rx: mpsc::Receiver<Command>,
    signal: Arc<Mutex<Control>>,
) {
    let mut active: Option<ActiveSession> = None;
    while let Some(command) = rx.recv().await {
        let stopping = signal
            .lock()
            .map(|control| control.stopping)
            .unwrap_or(true);
        if stopping && !matches!(&command, Command::Stop(_) | Command::Retire(_, _)) {
            // Dropping the reply denies queued work after shutdown intent.
            continue;
        }
        match command {
            Command::Enroll(reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(host.enroll());
                }
            }
            Command::Activate(account, reply) => {
                if reply.is_closed() {
                    continue;
                }
                let result = host.activate(account).and_then(|session| {
                    active = Some(session);
                    let next = SessionSignal {
                        session,
                        gate: host.gate(&session)?,
                    };
                    let mut control = match signal.lock() {
                        Ok(control) => control,
                        Err(_) => {
                            let _ = next.request_retirement();
                            return Err("Workspace signal unavailable".into());
                        }
                    };
                    if control.stopping {
                        let _ = next.request_retirement();
                        return Err("Workspace worker stopping".into());
                    }
                    control.active = Some(next.clone());
                    Ok(next)
                });
                if let Err(Ok(lost)) = reply.send(result) {
                    let _ = lost.request_retirement();
                    if host.retire(&lost.session).await.is_ok() {
                        active = None;
                        if let Ok(mut current) = signal.lock() {
                            current.active = None;
                        }
                    }
                }
            }
            Command::AddStdio(session, id, exe, args, cwd, reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(host.add_stdio(&session, id, &exe, &args, &cwd).await);
                }
            }
            Command::AddHttp(session, id, address, reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(host.add_http(&session, id, address).await);
                }
            }
            Command::Refresh(session, id, reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(host.refresh_connector(&session, &id).await);
                }
            }
            Command::Remove(session, id, reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(host.remove_connector(&session, &id).await);
                }
            }
            Command::Policy(session, function, policy, reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(host.set_connector_policy(&session, &function, policy));
                }
            }
            Command::Run(session, provider, prompt, names, reply) => {
                if !reply.is_closed() {
                    let result = host.run_agent(&session, &provider, &prompt, &names).await;
                    let _ = reply.send(result);
                }
            }
            // Retirement continues even if its acknowledgement is canceled.
            Command::Retire(session, reply) => {
                let result = host.retire(&session).await;
                if result.is_ok() {
                    active = None;
                    if let Ok(mut current) = signal.lock() {
                        current.active = None;
                    }
                }
                let _ = reply.send(result);
            }
            Command::Stop(reply) => {
                let result = match active {
                    Some(session) => host.retire(&session).await,
                    None => Ok(()),
                };
                if result.is_ok() {
                    if let Ok(mut current) = signal.lock() {
                        current.active = None;
                        current.stopped_cleanly = true;
                    }
                    let _ = reply.send(Ok(()));
                    return;
                }
                let _ = reply.send(result);
            }
        }
    }
    // Last sender dropped: best effort explicit retirement of tracked owners.
    // No claim of successful exit if cleanup failed.
    if let Some(session) = active {
        let _ = host.retire(&session).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_credentials::CredentialError;
    use axum::{routing::post, Json, Router};
    use serde_json::{json, Value};
    use std::{cell::RefCell, collections::HashMap, time::Duration};
    use tokio::net::TcpListener;

    #[derive(Default)]
    struct Fixture(RefCell<HashMap<(String, String), String>>);
    impl Store for Fixture {
        fn read(&self, s: &str, a: &str) -> Result<String, CredentialError> {
            self.0
                .borrow()
                .get(&(s.into(), a.into()))
                .cloned()
                .ok_or(CredentialError::Missing)
        }
        fn write(&self, s: &str, a: &str, v: &str) -> Result<(), CredentialError> {
            self.0.borrow_mut().insert((s.into(), a.into()), v.into());
            Ok(())
        }
        fn delete(&self, s: &str, a: &str) -> Result<(), CredentialError> {
            self.0.borrow_mut().remove(&(s.into(), a.into()));
            Ok(())
        }
    }
    const CHILD: &str = r#"
IFS= read -r line || exit 1
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}'
IFS= read -r line || exit 2
IFS= read -r line || exit 3
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"read","inputSchema":{"type":"object","additionalProperties":false}}]}}'
IFS= read -r line || exit 4
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"fixture"}]}}'
IFS= read -r line
"#;
    #[tokio::test]
    async fn connector_refresh_and_remove_are_exact_session_operations() {
        let dir = tempfile::tempdir().unwrap();
        let mut worker = WorkspaceWorker::start(dir.path().to_owned(), Fixture::default())
            .await
            .unwrap();
        let a = worker.enroll().await.unwrap();
        let b = worker.enroll().await.unwrap();
        let first = worker.activate(a).await.unwrap();
        let session = first.session();
        let script = CHILD.replace(
            r#"{"content":[{"type":"text","text":"fixture"}]}"#,
            r#"{"tools":[{"name":"new","inputSchema":{"type":"object","additionalProperties":false}}]}"#,
        );
        let args = vec!["-c".into(), script];
        worker
            .add_stdio(
                session,
                "local".into(),
                "/bin/sh".into(),
                args.clone(),
                "/".into(),
            )
            .await
            .unwrap();
        worker
            .set_policy(session, "local__read".into(), McpPolicy::Ask)
            .await
            .unwrap();
        // A canceled queued removal must not mutate the owner.
        let (tx, rx) = oneshot::channel();
        drop(rx);
        worker
            .submit(Command::Remove(session, "local".into(), tx))
            .unwrap();
        worker
            .refresh_connector(session, "local".into())
            .await
            .unwrap();
        assert!(worker
            .set_policy(session, "local__read".into(), McpPolicy::Ask)
            .await
            .is_err());
        worker
            .set_policy(session, "local__new".into(), McpPolicy::Ask)
            .await
            .unwrap();
        assert!(worker
            .remove_connector(session, "bad__id".into())
            .await
            .is_err());
        worker
            .remove_connector(session, "local".into())
            .await
            .unwrap();
        assert!(worker
            .refresh_connector(session, "local".into())
            .await
            .is_err());
        worker
            .add_stdio(
                session,
                "local".into(),
                "/bin/sh".into(),
                args.clone(),
                "/".into(),
            )
            .await
            .unwrap();
        worker.retire(&first).await.unwrap();
        let second = worker.activate(b).await.unwrap();
        let fresh = second.session();
        worker
            .add_stdio(fresh, "local".into(), "/bin/sh".into(), args, "/".into())
            .await
            .unwrap();
        assert!(worker
            .refresh_connector(session, "local".into())
            .await
            .is_err());
        assert!(worker
            .remove_connector(session, "local".into())
            .await
            .is_err());
        worker
            .refresh_connector(fresh, "local".into())
            .await
            .unwrap();
        worker
            .remove_connector(fresh, "local".into())
            .await
            .unwrap();
        worker.retire(&second).await.unwrap();
        worker.stop().await.unwrap();
    }

    #[tokio::test]
    async fn retirement_signal_interrupts_busy_agent_and_queue_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let mut worker = WorkspaceWorker::start(dir.path().to_owned(), Fixture::default())
            .await
            .unwrap();
        let a = worker.enroll().await.unwrap();
        let b = worker.enroll().await.unwrap();
        let first = worker.activate(a).await.unwrap();
        let session = first.session();
        worker
            .add_stdio(
                session,
                "local".into(),
                "/bin/sh".into(),
                vec!["-c".into(), CHILD.into()],
                "/".into(),
            )
            .await
            .unwrap();
        worker
            .set_policy(session, "local__read".into(), McpPolicy::Ask)
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(address) = listener.local_addr().unwrap() else {
            panic!("IPv4")
        };
        let server = tokio::spawn(async move {
            axum::serve(listener,Router::new().route("/v1/chat/completions",post(|Json(_):Json<Value>|async {
                Json(json!({"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":null,"tool_calls":[{"id":"one","type":"function","function":{"name":"local__read","arguments":"{}"}}]}}]}))
            }))).await.unwrap();
        });
        let provider = Arc::new(LocalModelProvider::for_test(address));
        let gate = first.gate();
        let mut events = gate.subscribe();
        let (tx, run) = oneshot::channel();
        worker
            .submit(Command::Run(
                session,
                provider,
                "question".into(),
                BTreeSet::from(["local__read".into()]),
                tx,
            ))
            .unwrap();
        let request = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request.tool, "local__read");
        for _ in 0..CAPACITY {
            let (tx, rx) = oneshot::channel::<Result<AccountId, String>>();
            worker.submit(Command::Enroll(tx)).unwrap();
            drop(rx);
        }
        // Queue full, but retirement must close the gate independently.
        let (tx, rx) = oneshot::channel();
        assert!(worker.submit(Command::Enroll(tx)).is_err());
        drop(rx);
        let _ = worker.retire(&first).await;
        assert!(gate.current_epoch().is_err());
        assert!(
            !gate
                .resolve(uuid::Uuid::parse_str(&request.id).unwrap(), true)
                .await
        );
        assert!(tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        // Barrier queued after all canceled enrollment work.
        let (tx, rx) = oneshot::channel();
        worker.tx.send(Command::Retire(session, tx)).await.unwrap();
        // A first retirement may have raced the queue drain and succeeded.
        let _ = receive(rx).await;
        let second = worker.activate(b).await.unwrap();
        assert!(first.request_retirement().is_ok());
        assert!(second.gate().current_epoch().is_ok());
        worker.retire(&second).await.unwrap();
        worker.stop().await.unwrap();
        worker.stop().await.unwrap();
        assert!(worker.current_signal().unwrap().is_none());
        assert!(worker.activate(a).await.is_err());
        server.abort();
    }
}
