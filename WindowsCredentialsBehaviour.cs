// --------------------------------------------------------------------------------------------------------------------
// <copyright file="WindowsCredentialsBehaviour.cs" company="Solidsoft Reply Ltd.">
//   Copyright (c) 2015 Solidsoft Reply Limited. All rights reserved.
// 
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
// 
//       http://www.apache.org/licenses/LICENSE-2.0
// 
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License. 
// </copyright>
// --------------------------------------------------------------------------------------------------------------------

namespace SolidsoftReply.BizTalk.Wcf.Security
{
    using System;
    using System.Configuration;
    using System.Security.Principal;
    using System.ServiceModel.Channels;
    using System.ServiceModel.Configuration;
    using System.ServiceModel.Description;
    using System.ServiceModel.Dispatcher;

    /// <summary>
    /// WCF behaviour to handle NTLM authentication against services in foreign domains.
    /// </summary>
    public class WindowsCredentialsBehaviour : BehaviorExtensionElement, IEndpointBehavior
    {
        /// <summary>
        /// The user name.
        /// </summary>
        [ConfigurationProperty("Username", DefaultValue = "")]
        public string Username
        {
            get
            {
                return (string)base["Username"];
            }

            set
            {
                base["Username"] = value;
            }
        }

        /// <summary>
        /// The password.
        /// </summary>
        [ConfigurationProperty("Password", DefaultValue = "")]
        public string Password
        {
            get
            {
                return (string)base["Password"];
            }

            set
            {
                base["Password"] = value;
            }
        }

        /// <summary>
        /// The Windows domain.
        /// </summary>
        [ConfigurationProperty("Domain", DefaultValue = "")]
        public string Domain
        {
            get
            {
                return (string)base["Domain"];
            }

            set
            {
                base["Domain"] = value;
            }
        }

        /// <summary>
        /// The Windows Impersonation level.  By default, the level is Identification.
        /// </summary>
        [ConfigurationProperty("ImpersonationLevel", DefaultValue = TokenImpersonationLevel.Identification)]
        public TokenImpersonationLevel ImpersonationLevel
        {
            get
            {
                return (TokenImpersonationLevel)base["ImpersonationLevel"];
            }

            set
            {
                base["ImpersonationLevel"] = value;
            }
        }

        /// <summary>
        /// Enables or disables the behaviour.
        /// </summary>
        [ConfigurationProperty("Enable", DefaultValue = true)]
        public bool Enable
        {
            get
            {
                return (bool)base["Enable"];
            }

            set
            {
                base["Enable"] = value;
            }
        }

        /// <summary>
        /// Creates a behavior extension based on the current configuration settings.
        /// </summary>
        /// <returns>
        /// The behavior extension.
        /// </returns>
        protected override object CreateBehavior()
        {
            return this;
        }

        /// <summary>
        /// Gets the type of behavior.
        /// </summary>
        public override Type BehaviorType
        {
            get
            {
                return typeof(WindowsCredentialsBehaviour);
            }
        }

        /// <summary>
        /// Implement to pass data at runtime to bindings to support custom behavior.
        /// </summary>
        /// <param name="endpoint">The endpoint to modify.</param>
        /// <param name="bindingParameters">The objects that binding elements require to support the behavior.</param>
        public void AddBindingParameters(ServiceEndpoint endpoint, BindingParameterCollection bindingParameters)
        {
            if (!this.Enable)
            {
                return;
            }
            var username = this.Username;
            var domain = this.Domain;

            if (bindingParameters != null)
            {
                var clientCredentials = endpoint.Behaviors.Find<ClientCredentials>();

                // If a user name was provided, then process the data to handle scenarios where the
                // domain is included in the user name.  Also, set the standard credentials as required.
                if (!string.IsNullOrWhiteSpace(username))
                {
                    var domainSlashIndex = username.IndexOf('\\');

                    // If no user credentials have already been set, set them here. This helps 
                    // ensure that the behaviour works better when not used for Windows authentication.
                    // It will favour credentials set explicitly in adapter configuration, but will
                    // use the credentials set on the bahviour if no credentials were configured.
                    var setCredentails = string.IsNullOrWhiteSpace(clientCredentials.UserName.UserName);

                    if (domainSlashIndex >= 0)
                    {
                        if (string.IsNullOrWhiteSpace(domain) ||
                            domain.ToLower() == username.Substring(0, domainSlashIndex).ToLower())
                        {
                            if (setCredentails)
                            {
                                clientCredentials.UserName.UserName = username;
                            }

                            domain = username.Substring(0, domainSlashIndex).ToLower();
                            username = username.Substring(domainSlashIndex + 1).ToLower();
                        }
                        else
                        {
                            // Domain clash - raise error.
                            throw new ApplicationException(
                                string.Format(
                                    SolidsoftReply.BizTalk.Wcf.Security.Properties.Resources.ExceptionDomainClash, domain, username));
                        }
                    }
                    else
                    {
                        if (setCredentails)
                        {
                            clientCredentials.UserName.UserName =
                                domain +
                                (string.IsNullOrWhiteSpace(domain) ? "" : @"\") +
                                username;
                        }
                    }

                    if (setCredentails)
                    {
                        clientCredentials.UserName.Password = this.Password;
                    }
                }

                // Set the Windows credentials
                clientCredentials.Windows.ClientCredential.UserName = username;
                clientCredentials.Windows.ClientCredential.Password = this.Password;
                clientCredentials.Windows.ClientCredential.Domain = domain;
                clientCredentials.Windows.AllowedImpersonationLevel = this.ImpersonationLevel;

                if (bindingParameters.Find<ClientCredentials>() == null)
                {
                    bindingParameters.Add(this);
                }
            }
            else
            {
                throw new ArgumentNullException("bindingParameters");
            }
        }

        /// <summary>
        /// Implements a modification or extension of the client across an endpoint.
        /// </summary>
        /// <param name="endpoint">The endpoint that is to be customized.</param>
        /// <param name="clientRuntime">The client runtime to be customized.</param>
        void IEndpointBehavior.ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {
        }

        /// <summary>
        /// Implements a modification or extension of the service across an endpoint.
        /// </summary>
        /// <param name="endpoint">The endpoint that exposes the contract.</param>
        /// <param name="endpointDispatcher">The endpoint dispatcher to be modified or extended.</param>
        void IEndpointBehavior.ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
        {
        }

        /// <summary>
        /// Implement to confirm that the endpoint meets some intended criteria.
        /// </summary>
        /// <param name="endpoint">The endpoint to validate.</param>
        void IEndpointBehavior.Validate(ServiceEndpoint endpoint)
        {
        }
    }
}
