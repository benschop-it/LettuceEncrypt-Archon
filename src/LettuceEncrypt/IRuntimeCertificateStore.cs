// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace LettuceEncrypt
{
    /// <summary>
    /// Manages certifactes during runtime
    /// </summary>
    public interface IRuntimeCertificateStore
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domainName"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        X509Certificate2 AddCertWithDomainName(string domainName, X509Certificate2 certificate);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domainName"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        X509Certificate2 AddChallengeCertWithDomainName(string domainName, X509Certificate2 certificate);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="domainName"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        bool GetCert(string domainName, out X509Certificate2? certificate);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domainName"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        bool GetChallengeCert(string domainName, out X509Certificate2? certificate);

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        bool AnyChallengeCert();
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        bool ContainsCertForDomain(string domainName);
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        IEnumerable<string> GetAllCertDomains();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        bool RemoveCert(string domainName);
        /// <summary>
        /// 
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        bool RemoveChallengeCert(string domainName);
    }
}
