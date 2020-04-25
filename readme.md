# Microsoft LDAP UserAccountControl Parser

A package for retrieving values from the Microsoft LDAP property UserAccountControl

https://support.microsoft.com/en-us/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties

## Usage

```golang
import "github.com/audibleblink/msldapuac"

uacProp := int64(514)
msldapuac.ParseUAC(uacProp)
// => [ "NORMAL_ACCOUNT", "ACCOUNTDISABLE" ]
```
