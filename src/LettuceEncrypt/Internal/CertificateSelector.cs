// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal
{
    internal class CertificateSelector : IServerCertificateSelector
    {
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger<CertificateSelector> _logger;
        private readonly IRuntimeCertificateStore _runtimeCertificateStore;

        public CertificateSelector(IOptions<LettuceEncryptOptions> options, ILogger<CertificateSelector> logger, IRuntimeCertificateStore runtimeCertificateStore)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _runtimeCertificateStore = runtimeCertificateStore;
        }

        public IEnumerable<string> SupportedDomains => _runtimeCertificateStore.GetAllCertDomains();

        public virtual void Add(X509Certificate2 certificate)
        {
            var preloaded = false;
            foreach (var dnsName in X509CertificateHelpers.GetAllDnsNames(certificate))
            {
                var selectedCert = _runtimeCertificateStore.AddCertWithDomainName(dnsName, certificate);

                // Call preload once per certificate, but only if the cetificate is actually selected to be used
                // for this domain. This is a small optimization which avoids preloading on a cert that may not be used.
                if (!preloaded && selectedCert == certificate)
                {
                    preloaded = true;
                    PreloadIntermediateCertificates(selectedCert);
                }
            }
        }

        public virtual void AddChallengeCert(X509Certificate2 certificate)
        {
            foreach (var dnsName in X509CertificateHelpers.GetAllDnsNames(certificate))
            {
                _runtimeCertificateStore.AddChallengeCertWithDomainName(dnsName, certificate);
            }
        }

        public void ClearChallengeCert(string dnsName)
        {
            _runtimeCertificateStore.RemoveChallengeCert(dnsName);
        }

        /// <summary>
        /// Registers the certificate for usage with domain unless there is already a newer cert for this domain.
        /// </summary>
        /// <param name="certs"></param>
        /// <param name="domainName"></param>
        /// <param name="certificate"></param>
        /// <returns>The certificate current selected to be used for this domain</returns>
        private X509Certificate2 AddWithDomainName(ConcurrentDictionary<string, X509Certificate2> certs, string domainName,
            X509Certificate2 certificate)
        {
            return certs.AddOrUpdate(
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

        public bool HasCertForDomain(string domainName) => _runtimeCertificateStore.ContainsCertForDomain(domainName);

        public X509Certificate2? Select(ConnectionContext context, string? domainName)
        {
#if NETCOREAPP3_1_OR_GREATER
            if (_runtimeCertificateStore.AnyChallengeCert())
            {
                // var sslStream = context.Features.Get<SslStream>();
                // sslStream.NegotiatedApplicationProtocol hasn't been set yet, so we have to assume that
                // if ALPN challenge certs are configured, we must respond with those.

                if (domainName != null && _runtimeCertificateStore.GetChallengeCert(domainName, out var challengeCert))
                {
                    _logger.LogTrace("Using ALPN challenge cert for {domainName}", domainName);

                    return challengeCert;
                }
            }
#elif NETSTANDARD2_0
#else
#error Update TFMs
#endif

            if (domainName == null || !_runtimeCertificateStore.GetCert(domainName, out var cert))
            {
                return _options.Value.FallbackCertificate;
            }

            return cert;
        }

        public void Reset(string domainName)
        {
            _runtimeCertificateStore.RemoveCert(domainName);
        }

        public bool TryGet(string domainName, out X509Certificate2? certificate)
        {
            return _runtimeCertificateStore.GetCert(domainName, out certificate);
        }

        private void PreloadIntermediateCertificates(X509Certificate2 certificate)
        {
            if (certificate.IsSelfSigned())
            {
                return;
            }

            // workaround for https://github.com/dotnet/aspnetcore/issues/21183
            using var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck
                }
            };

            var commonName = X509CertificateHelpers.GetCommonName(certificate);
            try
            {
                if (chain.Build(certificate))
                {
                    _logger.LogTrace("Successfully tested certificate chain for {commonName}", commonName);
                    return;
                }
            }
            catch (CryptographicException ex)
            {
                _logger.LogDebug(ex, "Failed to validate certificate chain for {commonName}", commonName);
            }

            _logger.LogWarning(
                "Failed to validate certificate for {commonName} ({thumbprint}). This could cause an outage of your app.",
                commonName, certificate.Thumbprint);
        }
    }
}
