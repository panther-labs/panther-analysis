from panther_base_helpers import crowdstrike_detection_alert_context, deep_get

LOLBAS_EXE = {
    "AppInstaller.exe",
    "At.exe",
    "Atbroker.exe",
    "Bash.exe",
    "Bitsadmin.exe",
    "CertOC.exe",
    "CertReq.exe",
    "Certutil.exe",
    "Cmd.exe",
    "Cmdkey.exe",
    "cmdl32.exe",
    "Cmstp.exe",
    "ConfigSecurityPolicy.exe",
    "Conhost.exe",
    "Control.exe",
    "Csc.exe",
    "Cscript.exe",
    "CustomShellHost.exe",
    "DataSvcUtil.exe",
    "Desktopimgdownldr.exe",
    "DeviceCredentialDeployment.exe",
    "Dfsvc.exe",
    "Diantz.exe",
    "Diskshadow.exe",
    "Dnscmd.exe",
    "Esentutl.exe",
    "Eventvwr.exe",
    "Expand.exe",
    "Explorer.exe",
    "Extexport.exe",
    "Extrac32.exe",
    "Findstr.exe",
    "Finger.exe",
    "fltMC.exe",
    "Forfiles.exe",
    "Ftp.exe",
    "Gpscript.exe",
    "Hh.exe",
    "IMEWDBLD.exe",
    "Ie4uinit.exe",
    "Ieexec.exe",
    "Ilasm.exe",
    "Infdefaultinstall.exe",
    "Installutil.exe",
    "Jsc.exe",
    "Ldifde.exe",
    "Makecab.exe",
    "Mavinject.exe",
    "Mmc.exe",
    "MpCmdRun.exe",
    "Msbuild.exe",
    "Msconfig.exe",
    "Msdt.exe",
    "Msedge.exe",
    "Mshta.exe",
    "Msiexec.exe",
    "Netsh.exe",
    "Odbcconf.exe",
    "OfflineScannerShell.exe",
    "OneDriveStandaloneUpdater.exe",
    "Pcalua.exe",
    "Pcwrun.exe",
    "Pktmon.exe",
    "Pnputil.exe",
    "Presentationhost.exe",
    "Print.exe",
    "PrintBrm.exe",
    "Psr.exe",
    "Rasautou.exe",
    "rdrleakdiag.exe",
    "Reg.exe",
    "Regasm.exe",
    "Regedit.exe",
    "Regini.exe",
    "Regsvcs.exe",
    "Regsvr32.exe",
    "Replace.exe",
    "Rpcping.exe",
    "Rundll32.exe",
    "Runexehelper.exe",
    "Runonce.exe",
    "Runscripthelper.exe",
    "Sc.exe",
    "Schtasks.exe",
    "Scriptrunner.exe",
    "Setres.exe",
    "SettingSyncHost.exe",
    "ssh.exe",
    "Stordiag.exe",
    "SyncAppvPublishingServer.exe",
    "Ttdinject.exe",
    "Tttracer.exe",
    "Unregmp2.exe",
    "vbc.exe",
    "Verclsid.exe",
    "Wab.exe",
    "winget.exe",
    "Wlrmdr.exe",
    "Wmic.exe",
    "WorkFolders.exe",
    "Wscript.exe",
    "Wsreset.exe",
    "wuauclt.exe",
    "Xwizard.exe",
    "fsutil.exe",
    "wt.exe",
}


def rule(event):
    if deep_get(event, "event", "event_simpleName") == "ProcessRollup2":
        if deep_get(event, "event", "event_platform") == "Win":
            exe = event.udm("process_name")

        return bool(exe.lower() in [x.lower() for x in LOLBAS_EXE])
    else:
        return False


def title(event):
    exe = deep_get(event, "event", "ImageFileName").split("\\")[-1]
    return f'LOLBAS execution - {exe} - {deep_get(event, "event", "CommandLine")}'


def dedup(event):
    # dedup string on "{aid}-{exe}"
    exe = event.udm("process_name")
    return f'{deep_get(event, "event", "aid")}-{exe}'


def alert_context(event):
    return crowdstrike_detection_alert_context(event) | {
        "MD5HashData": deep_get(event, "event", "MD5HashData"),
        "aid": deep_get(event, "aid"),
        "ParentBaseFileName": deep_get(event, "event", "ParentBaseFileName"),
        "ParentProcessId": deep_get(event, "event", "ParentProcessId"),
    }
