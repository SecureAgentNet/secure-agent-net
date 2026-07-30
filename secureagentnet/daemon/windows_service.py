r"""Optional Windows Service wrapper for the SecureAgentNet daemon.

Requires pywin32. To install as a Windows service (administrator prompt):
    python secureagentnet\daemon\windows_service.py install
    python secureagentnet\daemon\windows_service.py start
"""
from __future__ import annotations

import sys


try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError:
    # Guard so the file can be imported on non-Windows platforms without error.
    win32serviceutil = None  # type: ignore


if win32serviceutil is not None:
    class SecureAgentNetWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "SecureAgentNet"
        _svc_display_name_ = "SecureAgentNet Endpoint Security Engine"
        _svc_description_ = "Background engine for the SecureAgentNet AI agent security monitor."

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            from secureagentnet.daemon.daemon import run_daemon
            run_daemon()

    def main():
        win32serviceutil.HandleCommandLine(SecureAgentNetWindowsService)

else:
    def main():
        print("pywin32 is required for Windows service management.")
        print("Install it with: pip install pywin32")
        sys.exit(1)


if __name__ == "__main__":
    main()
