// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal class CheckForRenewalState : AcmeState
    {
        private readonly ILogger<CheckForRenewalState> _logger;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IDomainLoader _domains;
        private readonly CertificateSelector _selector;
        private readonly IClock _clock;

        public CheckForRenewalState(
            AcmeStateMachineContext context,
            ILogger<CheckForRenewalState> logger,
            IOptions<LettuceEncryptOptions> options,
            IDomainLoader domains,
            CertificateSelector selector,
            IClock clock) : base(context)
        {
            _logger = logger;
            _options = options;
            _domains = domains;
            _selector = selector;
            _clock = clock;
        }

        public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var checkPeriod = _options.Value.RenewalCheckPeriod;
                var daysInAdvance = _options.Value.RenewDaysInAdvance;
                if (!checkPeriod.HasValue || !daysInAdvance.HasValue)
                {
                    _logger.LogInformation("Automatic certificate renewal is not configured. Stopping {service}",
                        nameof(AcmeCertificateLoader));
                    return MoveTo<TerminalState>();
                }

                var domains = await _domains.GetDomainsAsync(cancellationToken);
                foreach (var domain in domains)
                {
                    if (_logger.IsEnabled(LogLevel.Debug))
                    {
                        _logger.LogDebug("Checking certificates' renewals for {hostname}", domain);
                    }

                    if (!_selector.TryGet(domain, out var cert)
                           || cert == null
                           || cert.NotAfter <= _clock.Now.DateTime + daysInAdvance.Value)
                    {
                        return MoveTo<BeginCertificateCreationState>();
                    }
                }
                await Task.Delay(checkPeriod.Value, cancellationToken);
            }

            return MoveTo<TerminalState>();
        }
    }
}
