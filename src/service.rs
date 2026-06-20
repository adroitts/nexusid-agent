//! Windows Service integration — runs the agent under the Service Control Manager so it starts on boot
//! and runs in the background, the equivalent of the systemd unit / launchd plist on Linux/macOS.
//!
//! `nexus-agent service install -c <config>` registers the service (LocalSystem, autostart) pointing the
//! SCM at `nexus-agent run-service --config <config>`; `service uninstall` removes it. The whole module
//! is Windows-only — on other platforms it compiles to nothing.
#![cfg(windows)]

use crate::config::Config;
use crate::error::{AgentError, Result};
use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "NexusAgent";
const DISPLAY_NAME: &str = "NexusID Sync Agent";

windows_service::define_windows_service!(ffi_service_main, service_main);

/// SCM entry — invoked by `nexus-agent run-service` (the binPath the Service Control Manager launches).
pub fn run(config_path: &str) -> Result<()> {
    // The C-callback service_main can't take args, so stash the config path for it to read.
    std::env::set_var("NEXUS_AGENT_CONFIG", config_path);
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| AgentError::Config(format!("service dispatcher: {e}")))
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("nexus-agent service error: {e}");
    }
}

fn run_service() -> windows_service::Result<()> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
    let set_status = |state: ServiceState, accept: ServiceControlAccept| {
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };
    set_status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;

    // Run the agent on its own tokio runtime in a worker thread; the SCM stop ends the process.
    let config_path = std::env::var("NEXUS_AGENT_CONFIG").unwrap_or_else(|_| "config.toml".into());
    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Runtime::new() {
            let _ = rt.block_on(async {
                match Config::load(&config_path) {
                    Ok(cfg) => crate::runner::run(cfg).await,
                    Err(e) => {
                        tracing::error!("nexus-agent service config error: {e}");
                        Ok(())
                    }
                }
            });
        }
    });

    // Block until the SCM asks us to stop, then report Stopped and exit (ends the worker).
    let _ = stop_rx.recv();
    set_status(ServiceState::StopPending, ServiceControlAccept::empty())?;
    set_status(ServiceState::Stopped, ServiceControlAccept::empty())?;
    std::process::exit(0);
}

/// Register the service (LocalSystem, autostart) and start it.
pub fn install(config_path: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| AgentError::Config(format!("open SCM (run as Administrator): {e}")))?;
    let exe = std::env::current_exe().map_err(|e| AgentError::Config(format!("current exe: {e}")))?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![
            OsString::from("run-service"),
            OsString::from("--config"),
            OsString::from(config_path),
        ],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(|e| AgentError::Config(format!("create service: {e}")))?;
    let _ = service.set_description("NexusID hybrid AD/DB sync agent");
    service
        .start(&[] as &[&OsString])
        .map_err(|e| AgentError::Config(format!("start service: {e}")))?;
    Ok(())
}

/// Ensure the service is running with the current config. If it's already registered (e.g. by the MSI),
/// restart it so it picks up freshly-written config; otherwise register + start it.
pub fn ensure_running(config_path: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| AgentError::Config(format!("open SCM (run as Administrator): {e}")))?;
    match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(service) => {
            // Already registered (typically by the MSI). Best-effort stop, then start with new config.
            let _ = service.stop();
            service
                .start(&[] as &[&OsString])
                .map_err(|e| AgentError::Config(format!("start service: {e}")))?;
            Ok(())
        }
        Err(_) => install(config_path),
    }
}

/// Stop and remove the service.
pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| AgentError::Config(format!("open SCM (run as Administrator): {e}")))?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
        )
        .map_err(|e| AgentError::Config(format!("open service: {e}")))?;
    let _ = service.stop();
    service
        .delete()
        .map_err(|e| AgentError::Config(format!("delete service: {e}")))?;
    Ok(())
}
