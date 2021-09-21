// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace LettuceEncrypt.Internal
{
    internal class InMemoryRuntimeCertificateStore : IRuntimeCertificateStore
    {
        private readonly ConcurrentDictionary<string, X509Certificate2> _certs =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, X509Certificate2> _challengeCerts =
            new(StringComparer.OrdinalIgnoreCase);

        public X509Certificate2 AddCertWithDomainName(string domainName, X509Certificate2 certificate)
        {
            return _certs.AddOrUpdate(
                domainName,
                certificate,
                (_, currentCert) =>
                {
                    if (currentCert == null || certificate.NotAfter >= currentCert.NotAfter)
                    {
                        return certificate;
                    }

                    return currentCert;
                });
        }

        public X509Certificate2 AddChallengeCertWithDomainName(string domainName, X509Certificate2 certificate)
        {
            return _challengeCerts.AddOrUpdate(
                domainName,
                certificate,
                (_, currentCert) =>
                {
                    if (currentCert == null || certificate.NotAfter >= currentCert.NotAfter)
                    {
                        return certificate;
                    }

                    return currentCert;
                });
        }

        public bool GetCert(string domainName, out X509Certificate2? certificate)
        {
            return _certs.TryGetValue(domainName, out certificate);
        }

        public bool GetChallengeCert(string domainName, out X509Certificate2? certificate)
        {
            return _challengeCerts.TryGetValue(domainName, out certificate);
        }

        public bool RemoveCert(string domainName)
        {
            return _certs.TryRemove(domainName, out _);
        }

        public bool RemoveChallengeCert(string domainName)
        {
            return _challengeCerts.TryRemove(domainName, out _);
        }

        public bool AnyChallengeCert()
        {
            return _challengeCerts.Count > 0;
        }

        public bool ContainsCertForDomain(string domainName)
        {
            return _certs.ContainsKey(domainName);
        }

        public IEnumerable<string> GetAllCertDomains()
        {
            return _certs.Keys;
        }
    }
}
