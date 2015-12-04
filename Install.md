Add the behaviour assembly to the GAC. 

gacutil -if <path>/olidsoftReply.BizTalk.Wcf.Security.WindowsCredentials.dll

Register the behaviour code in machine.config using the following XML:

      <behaviorExtensions>
        <add name="WindowsCredentialsBehaviour" type="SolidsoftReply.BizTalk.Wcf.Security.WindowsCredentialsBehaviour, SolidsoftReply.BizTalk.Wcf.Security.WindowsCredentials, Version=1.0.0.0, Culture=neutral, PublicKeyToken=95ae79fd342bf11e" />
      </behaviorExtensions>


There are two .NET machine.config files for 32 and 64 bit environments.  Update both.  They are generally located at:

C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config

If the behaviour is being used in BizTalk Server, add it as an Endpoint Behaviour on the Behviour tab of the WCF Custom adapter configuration dialog.  This includes configuring the username, password and domain, as well as the imprsonation level.
