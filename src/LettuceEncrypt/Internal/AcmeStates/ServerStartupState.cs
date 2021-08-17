// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal class ServerStartupState : AcmeState
    {
        private readonly LettuceEncryptDomains _domains;
        private readonly StartupCertificateLoader _certLoader;
        private readonly CertificateSelector _selector;
        private readonly ILogger<ServerStartupState> _logger;

        public ServerStartupState(
            AcmeStateMachineContext context,
            LettuceEncryptDomains domains,
            StartupCertificateLoader certLoader,
            CertificateSelector selector,
            ILogger<ServerStartupState> logger) :
            base(context)
        {
            _domains = domains;
            _certLoader = certLoader;
            _selector = selector;
            _logger = logger;
        }

        public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            _logger.LogDebug("Loading existing certificates.");
            await _certLoader.LoadAsync(cancellationToken);

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
