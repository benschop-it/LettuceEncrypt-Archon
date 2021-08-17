// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal class ServerStartupState : AcmeState
    {
        private readonly LettuceEncryptDomains _domains;
        private readonly IEnumerable<ICertificateSource> _certSources;
        private readonly CertificateSelector _selector;
        private readonly ILogger<ServerStartupState> _logger;

        public ServerStartupState(
            AcmeStateMachineContext context,
            LettuceEncryptDomains domains,
            IEnumerable<ICertificateSource> certSources,
            CertificateSelector selector,
            ILogger<ServerStartupState> logger) :
            base(context)
        {
            _domains = domains;
            _certSources = certSources;
            _selector = selector;
            _logger = logger;
        }

        public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            _logger.LogDebug("Loading existing certificates.");

            var allCerts = new List<X509Certificate2>();
            foreach (var certSource in _certSources)
            {
                var certs = await certSource.GetCertificatesAsync(cancellationToken);
                allCerts.AddRange(certs);
            }

            // Add newer certificates first. This avoid potentially unnecessary cert validations on older certificates
            foreach (var cert in allCerts.OrderByDescending(c => c.NotAfter))
            {
                _logger.LogDebug("Loading certificate: {cert}", cert.FriendlyName);
                _selector.Add(cert);
            }

            var domainSets = await _domains.GetDomainsAsync(cancellationToken);
            var hasCertForAllDomains = domainSets.All(set => set.All(_selector.HasCertForDomain));
            if (hasCertForAllDomains)
            {
                _logger.LogDebug("Certificate for {domainNames} already found.", domainSets);
                return MoveTo<CheckForRenewalState>();
            }

            return MoveTo<BeginCertificateCreationState>();
        }
    }
}
