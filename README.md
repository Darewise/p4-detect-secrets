# p4-detect-secrets
Secret detections for your perforce project.

## About

The goal of the project is to prevent secrets from entering your perforce depot or at least document them.

Once setup, If you try to **shelve** or **submit** secrets in the depot, you should be blocked by a perforce trigger.

Then you can either remove the secret from the **Changelist** or update the secrets baseline and add it to your **Changelist**.

The secret detection part is made by the [Yelp detect-secrets pip package](https://github.com/Yelp/detect-secrets).

## Setup

The Python scripts are made for Python version 3.7.7 or higher.

### Trigger instalation

#### - Copy `server-triggers/secret_trigger.py` to your perforce server or perforce depot.
#### - You need to install python in your perforce server and the pip packages listed inside `requirements.txt`.
#### - Then use the `p4 triggers` command to setup the triggers conditions

```
secret_shelve shelve-commit //... "python3 secret_trigger.py %user% %client% %change%"
# or/and
secret_commit change-content //... "python3 secret_trigger.py %user% %client% %change% --is-change-content"
```

> warning! if you use swarm, place the triggers BEFORE the swarm `shelve-commit` to avoid having secrets stored in swarm history!

#### - Make the `client-tools` scripts accessible to your p4 users.

You can call `init_baseline.py > .secrets.baseline` from your workspace root, to scan your workspace for secrets and create the initial baseline file (only need to be done once).

When a shelve or submit is blocked by the trigger, the user can either remove the secret and try again or use the script `update_baseline.py CL_NUMBER` to update the baseline and add it to the CL.

We have added it as a [p4v custom tool](https://www.perforce.com/manuals/p4v/Content/P4V/advanced_options.custom.html) so it's easier to use by our users directly from p4v interface.
>customtools.xml
```
 <CustomToolDef>
  <Definition>
   <Name>Audit Secrets</Name>
   <Command>cmd.exe</Command>
   <Arguments>/c C:\Darewise\workspace\corvus\Tools\Perforce\../detect-secrets/update_baseline.bat %p</Arguments>
   <Shortcut></Shortcut>
  </Definition>
  <Console>
   <CloseOnExit>false</CloseOnExit>
  </Console>
  <AddToContext>true</AddToContext>
 </CustomToolDef>
 ```
