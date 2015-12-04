# WindowsCredentialsBehaviour
A simple WCF behaviour to handle the configuration of Windows credentials for SSPI Negotiate authentication.

In scenarios where WCF is used on the client side to interact with services that support Windows integrated authentication, all that is required is to ensure that the process hosting the client is running in the appropriate security context.  However, this is not always possible.  In that case, the Windows credentials must be provided.  This endpoint behaviour provides a mechanism for doing this.

The issue often arises when using the WCF-Custom adapters in BizTalk Server.  Although the adapter configuration dialog supports the configuration of credentials, these are not Windows credentials and are ignored in scenarios where Windows authentication is required by the service.  This behaviour can be configured in the Send adapter to handle SSPI authentication. 
