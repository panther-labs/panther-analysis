from panther_base_helpers import (
    filter_crowdstrike_fdr_event_type,
    get_crowdstrike_field,
)
from panther_base_helpers import deep_get

LOLBAS_EXE = { "AppInstaller.exe",
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
    }

def rule(event):

    if deep_get(event, "event", "event_simpleName") == "ProcessRollup2" and deep_get(event, "event", "event_platform") == "Win":

        exe = deep_get(event, "event", "ImageFileName").split("\\")[-1]

        if exe.lower() in [x.lower() for x in LOLBAS_EXE]:
            return True
    else:
        return False

def title(event):
    exe = deep_get(event, "event", "ImageFileName").split("\\")[-1]
    return (
        f'LOLBAS execution - {exe} - {deep_get(event, "event", "CommandLine")}'
    )

def dedup(event):
    exe = deep_get(event, "event", "ImageFileName").split("\\")[-1]

    return f'{deep_get(event, "event", "aid")}-{exe}'

def alert_context(event):
    return {
        "MD5HashData": deep_get(event, "event", "MD5HashData"),
        "aid": deep_get(event, "aid"),
        "ParentBaseFileName": deep_get(event, "event", "ParentBaseFileName"),
        "ParentProcessId": deep_get(event, "event", "ParentProcessId")
    }
