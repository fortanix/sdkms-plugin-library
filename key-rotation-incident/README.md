# Notify key rotation reminder as ServiceNow Incidents

This plugin can be used to monitor Fortanix DSM key rotation schedules and generate 
alerts using ServiceNow Incidents. The plugin scans all keys across Fortanix DSM Group(s)
it is a member of. Based on 90, 60, or 30 days prior to a time period that is
input to the plugin, if the key creation date breaches this threshold, an Incident
is generated in ServiceNow. For any key, a minimum of three Incidents will be
generated in ServiceNow. No new Incidents are generated if the key creation date
surpasses the specified time period threshold. The plugin also allows querying
ServiceNow for a list of Incidents relevant to this workflow.

## Input Commands

The plugin accepts a JSON object as input with a set of fields that vary based on
the operation. Most operational commands require the following two fields:

- `operation`: String identifying the operation to execute, see below for a full list.
- `secret_id`: String identifying the Fortanix DSM secret object containing the ServiceNow
    credentials. This is not required for the `configure` operation and is instead output.

Some operations require more fields in the input as noted below.

### Configure
`configure`: generates a new secret with ServiceNow credentials and other parameters
it receives as input in a DSM security object named randomly.

The input parameters are:

- `endpoint`: String, obtained from ServiceNow
- `api_key`: String, obtained from ServiceNow, alternatively for username/password
- `username`: String, (optional) obtained from ServiceNow
- `password`: String, (optional) obtained from ServiceNow
- `schedule`: Number, (optional) count of days after a key creation date it is supposed
  to be rotated on. This is the time period threshold used to compute the 90, 60, or 30 day
  reminder notifications. Default value is 365.
- `tag`: String, used for ServiceNow Incident management. Default value is "ftnxreminder".
- `message`: String, (optional) used for ServiceNow Incident description. Default value is
  "This is a reminder to rotate the following key"
- `params`: String, (optional) comma-separated list of column names used to fetch ServiceNow
  Incident records

The output contains a JSON object with a key called `secret_id` that is the UUID of the 
DSM secret and will be used in all subsequent operations.  The ServiceNow Incident API key
or credentials needs to have permission to make REST API calls as well as authorized to
GET or POST Incidents into the Table API.

### List Keys
`list-keys`: fetches all relevant keys that are due for rotation either 90, 60, or 30 days
prior to the configured or specified schedule. Plugin will consider keys across all
Fortanix DSM groups it is a member of.

The input parameters are:

- `schedule`: Number, (optional) count of days after a key creation date it is supposed
  to be rotated on
- `filter`: String, (optional) Fortanix DSM Security Object Type(s) to select. Default is empty,
  which selects all object types. Can be a single type or comma-separated list of types.

The output contains a JSON object array of keys that are due for rotation either 90, 60,
or 30 days prior to the configured or specified schedule, found across groups within
Fortanix DSM that the plugin is a member of.

### List ServiceNow Incidents
`list-incidents`: fetches ServiceNow Incidents related to the Fortanix DSM keys
that are or were due for rotation.

The input parameters are:

- `secret_id`: String, UUID of the Fortanix DSM Security Object obtained from `configure` operation.
- `params`: String, (optional) comma-separated list of ServiceNow Incident column names. Default value is
  "number,short_description,opened_at,urgency"

The output contains a JSON object array of ServiceNow Incidents corresponding to keys in
Fortanix DSM that are or were due for rotation. The `params` value overrides the corresponding information
stored in the `secret_id` metadata from the `configure` operation.

### Notify ServiceNow Incidents
`notify-incidents`: generates a ServiceNow Incident per Fortanix DSM key that is due for
rotation either 90, 60, or 30 days prior to the configured or specified schedule.

The input parameters are:

- `secret_id`: String, UUID of the Fortanix DSM Security Object obtained from `configure` operation.
- `schedule`: Number, (optional) count of days after a key creation date it is supposed to be rotated on
- `notify_again`: Boolean, (optional) whether to create a new ServiceNow Incident. Default is false.
- `filter`: String, (optional) Fortanix DSM Security Object Type to select. Default is empty,
  which selects all object types. Can be a single type or comma-separated list of types.

The output contains a JSON object array of keys that are due for rotation either 90, 60, or 30 days
prior to the configured or specified schedule, found across groups within Fortanix DSM that the plugin is 
a member of.

## Example Usage

Invoke the plugin with the following input to check for Fortanix DSM keys due for rotation:
```
{
  "operation": "list-keys",
  "schedule": 365
}

```
If pertinent keys are found, the output will be an array of groups of Security Object(s) as follows:
```
{
  "d7993e29-5a28-439a-9c26-b2d0c2a4960b": [
    {
      "notify": 2,
      "created": "20211202T160910Z",
      "key": "tq-root-key",
      "meta": {
        "foo-key": "bar-value"
      }
    }
  ],
  "07f85883-adaf-4a6c-a040-ffed46dfd349": {}
}
```
Note: the `schedule` parameter is optional and helpful for testing the integration or
troubleshooting the plugin. The keys are segregated into Fortanix DSM Group UUIDs. Each key
has a `notify` rating of 1, 2, or 3 that corresponds to 90, 60, and 30 days of lead time
prior to the rotation schedule. Key may include a `meta` object that may key-value pairs,
and also include the ServiceNow Incident number, the escalation date and its notification rating.


Now that you have confirmed the presence of Fortanix DSM key(s) in one or more Fortanix DSM
group(s) that are due for rotation per schedule, you may invoke the plugin with the following
input to initialize the ServiceNow integration:
```
{
  "operation": "configure",
  "endpoint": "dev50668.service-now.com",
  "api_key": "Zm9ydGFuaXg6dUlXck9PcCVmTzh...",
    "_OR_": "api_key or username+password",
  "username": "fortanix",
  "password": "uIWrOOp...."
  "schedule": 365,
  "tag": "ftnxreminder",
  "message": "This is a reminder to rotate the following key",
}
```
If successful, you will see output like this:
```
{
  "secret_id": "6c7cc3ec-1de6-4526-b272-1e3addd120b4"
}
```
Note: you can copy the JSON output key and value or just the value to substitute in latter operations.

To check if there are any ServiceNow Incidents, run the `list-incidents`, which is a read-only operation
using the `secret_id` input:

```
{
  "operation": "list-incidents",
  "secret_id": "ecb3f5e4-fa46-4ed9-aef4-3bed49141535"
}

```
The output should list the ServiceNow Incidents, that are related to any previously notified Fortanix DSM keys.
If there were no events the output will be as follows.

If the `secret_id` is correct you'd see an output like this:
```
{
  "error": {
    "detail": "Records matching query not found. Check query parameter or offset parameter",
    "message": "No Record found"
  },
  "status": "failure"
}
```

The main operation as per the objective of this plugin is `notify-incidents`. Based on the `list-keys` output
this operation will trigger ServiceNow and create new Incidents.
```
{
  "operation": "notify-incidents",
  "secret_id": "ecb3f5e4-fa46-4ed9-aef4-3bed49141535",
  "schedule": 365
}
```
If the `secret_id` is correct you'd see an output like this:
```
{
  "07f85883-adaf-4a6c-a040-ffed46dfd349": {},
  "d7993e29-5a28-439a-9c26-b2d0c2a4960b": [
    {
      "notify": 2,
      "meta": {
        "ftnxreminder2": "20221013T220549Z",
        "ftnxreminder2-incident": "INC0010073",
        "foo-key": "bar-value"
      },
      "created": "20211202T160910Z",
      "type": "RSA",
      "key": "tq-root-key"
    }
  ]
}
```
Note: the `schedule` parameter is optional again, but shown here for completeness.
The custom_metadata of the keys are updated with the ServiceNow Incident details. You may change the
`schedule` to see the impact of reversing or forwarding the time period on `list-keys` and `notify-incidents` operations.

To check if there are any ServiceNow Incidents, run the `list-incidents`, which is a read-only operation
using the `secret_id` input:
```
{
  "operation": "list-incidents",
  "secret_id": "ecb3f5e4-fa46-4ed9-aef4-3bed49141535"
}
```
The output should list the ServiceNow Incidents, that are related to any previously notified Fortanix DSM keys.
If there were no events the output will be empty or simply `{}`.

If the `secret_id` is correct you'd see an output like this:
```
[
  {
    "opened_at": "2022-10-13 22:05:48",
    "urgency": "2",
    "short_description": "This is a reminder to rotate the following key: tq-root-key #ftnxreminder2",
    "number": "INC0010073"
  }
]
```

Invoke the plugin one more time to check for Fortanix DSM keys due for rotation:
```
{
  "operation": "list-keys",
  "schedule": 325
}
```
If pertinent keys are found, the output will be an array of groups of Security Object(s) as follows:
```
{
  "07f85883-adaf-4a6c-a040-ffed46dfd349": {},
  "d7993e29-5a28-439a-9c26-b2d0c2a4960b": [
    {
      "meta": {
        "ftnxreminder2": "20221013T220549Z",
        "ftnxreminder2-incident": "INC0010073",
        "foo-key": "bar-value"
      },
      "key": "tq-root-key",
      "type": "RSA",
      "notify": 3,
      "created": "20211202T160910Z"
    }
  ]
}
```
Note: the `schedule` parameter is brought forward by reducing the time to 325 days. This simulates a time
progression of 40 days i.e. 365 - 325. The output contains `notify` value of 3, which means it is the last 
reminder into ServiceNow.

Invoke the plugin one last time to notify ServiceNow:
```
{
  "operation": "notify-incidents",
  "schedule": 325
}
```
Note: there will be another Incident created in ServiceNow and the Fortanix DSM key custom_metadata
will be updated accordingly:
```
{
  "07f85883-adaf-4a6c-a040-ffed46dfd349": {},
  "d7993e29-5a28-439a-9c26-b2d0c2a4960b": [
    {
      "key": "tq-root-key",
      "type": "RSA",
      "created": "20211202T160910Z",
      "meta": {
        "ftnxreminder2": "20221013T220549Z",
        "ftnxreminder2-incident": "INC0010073",
        "ftnxreminder3": "20221013T221410Z"
        "ftnxreminder3-incident": "INC0010074",
        "foo-key": "bar-value"
      },
      "notify": 3
    }
  ]
}
```
Note: the `list-incidents` should reveal two records from ServiceNow corresponding to the 60 day (notify2), and
30 day (notify3) reminders related to this Fortanix DSM key.
```
[
  {
    "urgency": "2"
    "short_description": "This is a reminder to rotate the following key: tq-root-key #ftnxreminder2",
    "opened_at": "2022-10-13 22:05:48",
    "number": "INC0010073",
  },
  {
    "urgency": "3",
    "short_description": "This is a reminder to rotate the following key: tq-root-key #ftnxreminder3",
    "opened_at": "2022-10-13 22:14:10"
    "number": "INC0010074",
  }
]
```

And finally, by progressing the time even further we can validate there are no more keys that are due for rotation.

Invoke the plugin with `list-keys` with:
```
{
  "operation": "list-keys",
  "schedule": 305,
}
```
To find the results as:
```
{
  "07f85883-adaf-4a6c-a040-ffed46dfd349": {},
  "d7993e29-5a28-439a-9c26-b2d0c2a4960b": {}
}
```



## References

 * [Fortanix DSM key lifecycle documentation]https://support.fortanix.com/hc/en-us/articles/360038354592-User-s-Guide-Fortanix-Data-Security-Manager-Key-Lifecycle-Management
 * [ServiceNow Table API for CRUD operations on Incidents]https://docs.servicenow.com/bundle/tokyo-application-development/page/integrate/inbound-rest/concept/c_TableAPI.html
 * [ServiceNow documentation for retrieving Incidents]https://docs.servicenow.com/bundle/tokyo-application-development/page/integrate/inbound-rest/task/t_GetStartedRetrieveExisting.html
 * [ServiceNow reference for REST API]https://docs.servicenow.com/en-US/bundle/tokyo-application-development/page/build/applications/concept/api-rest.html
 * [ServiceNow reference for REST API]https://docs.servicenow.com/en-US/bundle/tokyo-application-development/page/build/applications/concept/api-rest.html
