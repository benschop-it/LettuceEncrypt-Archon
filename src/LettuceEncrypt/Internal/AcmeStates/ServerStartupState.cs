// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates;

internal class ServerStartupState : AcmeState
{
    private readonly IDomainLoader _domainLoader;
    private readonly StartupCertificateLoader _certLoader;
    private readonly CertificateSelector _selector;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly ILogger<ServerStartupState> _logger;

    public ServerStartupState(
        AcmeStateMachineContext context,
        IDomainLoader domainLoader,
        StartupCertificateLoader certLoader,
        CertificateSelector selector,
        IOptions<LettuceEncryptOptions> options,
        ILogger<ServerStartupState> logger) :
        base(context)
    {
        _domainLoader = domainLoader;
        _certLoader = certLoader;
        _selector = selector;
        _options = options;
        _logger = logger;
    }

    public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("Loading existing certificates.");
        await _certLoader.LoadAsync(cancellationToken);

        IEnumerable<IDomainCert> allDomains = new List<IDomainCert>();

        foreach (var domainNames in _options.Value.DomainNames)
        {
            var domains = await _domainLoader.GetDomainCertsAsync(cancellationToken, domainNames, true);
            allDomains = allDomains.Concat(domains);
        }
        var hasCertForAllDomains = true;
        foreach (var domains in allDomains)
        {
            hasCertForAllDomains = hasCertForAllDomains && await _selector.HasCertForDomainAsync(domains);

            if (!hasCertForAllDomains) break;
        }

        if (hasCertForAllDomains)
        {
            _logger.LogDebug("Certificate for all domain names already found.");
            return MoveTo<CheckForRenewalState>();
        }

        return MoveTo<BeginCertificateCreationState>();
    }
}
