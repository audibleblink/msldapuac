# Microsoft LDAP UserAccountControl Parser

A package for retrieving values from the Microsoft LDAP property UserAccountControl

## Usage

```golang
import "github.com/audibleblink/msldapuac"

uacProp := int64(514)
msldapuac.ParseUAC(uacProp)
// => [ "NORMAL_ACCOUNT", "ACCOUNTDISABLE" ]
```
