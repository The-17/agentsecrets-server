import re

with open('/home/theapiartist/work/SecretsAPI/apps/telemetry/management/commands/calculate_metrics.py', 'r') as f:
    content = f.read()

proxy_stats_str = '''            total_calls=Sum('proxy_calls'),
            total_blocked=Sum('proxy_blocked'),
            total_redacted=Sum('proxy_redacted'),
            secrets_resolved=Sum('secrets_resolved'),
            total_proxy_duration_ms=Sum('total_proxy_duration_ms'),
            proxy_calls_daemon=Sum('proxy_calls_daemon'),
            proxy_calls_transient=Sum('proxy_calls_transient'),
            proxy_calls_mcp=Sum('proxy_calls_mcp'),
            proxy_calls_direct=Sum('proxy_calls_direct'),
            developer_commands=Sum('developer_commands'),
            ssrf_attempts_blocked=Sum('ssrf_attempts_blocked'),
            allowlist_violations=Sum('allowlist_violations'),
            response_redactions=Sum('response_redactions'),
            process_verifications_failed=Sum('process_verifications_failed'),
            production_write_challenges=Sum('production_write_challenges'),
            keychain_resolution_ms=Sum('keychain_resolution_ms'),
            session_refresh_ms=Sum('session_refresh_ms'),
            interactive_prompts_shown=Sum('interactive_prompts_shown'),
            interactive_prompts_skipped=Sum('interactive_prompts_skipped'),
            drift_diffs_detected=Sum('drift_diffs_detected'),
            log_chain_verifications=Sum('log_chain_verifications'),
            tampering_detected=Sum('tampering_detected'),
            identity_anonymous_calls=Sum('identity_anonymous_calls'),
            identity_declared_calls=Sum('identity_declared_calls'),
            identity_issued_calls=Sum('identity_issued_calls'),
            capability_violations_blocked=Sum('capability_violations_blocked'),
            process_verifications_passed=Sum('process_verifications_passed'),
            errors_auth_count=Sum('errors_auth_count'),
            errors_keychain_count=Sum('errors_keychain_count'),
            errors_secrets_count=Sum('errors_secrets_count'),
            errors_network_count=Sum('errors_network_count'),
            errors_system_count=Sum('errors_system_count'),
            errors_unknown_count=Sum('errors_unknown_count')'''

content = content.replace('''            total_calls=Sum('proxy_calls'),
            total_blocked=Sum('proxy_blocked'),
            total_redacted=Sum('proxy_redacted')''', proxy_stats_str)


typos_str = '''        # ──────────────────────────────────────────────
        # 8b. TYPOS USAGE
        # ──────────────────────────────────────────────
        typos_usage = {}
        typos_snapshots = (
            TelemetrySnapshot.objects
            .filter(
                Q(client_timestamp__date__lte=target_date) | 
                Q(client_timestamp__isnull=True, created_at__date__lte=target_date)
            )
            .exclude(typos={})
            .only('typos')
        )
        for snapshot in typos_snapshots:
            for typo, count in snapshot.typos.items():
                typos_usage[typo] = typos_usage.get(typo, 0) + count

        # ──────────────────────────────────────────────
        # 9. SAVE — ATOMIC UPDATE'''

content = content.replace('''        # ──────────────────────────────────────────────
        # 9. SAVE — ATOMIC UPDATE''', typos_str)

defaults_str = '''                'total_proxy_calls': proxy_stats['total_calls'] or 0,
                'total_proxy_blocked': proxy_stats['total_blocked'] or 0,
                'total_proxy_redacted': proxy_stats['total_redacted'] or 0,
                'command_usage': command_usage,
                'environment_distribution': env_dist,
                'integration_usage': integration_usage,
                'total_secrets_resolved': proxy_stats['secrets_resolved'] or 0,
                'total_proxy_duration_ms': proxy_stats['total_proxy_duration_ms'] or 0,
                'total_proxy_calls_daemon': proxy_stats['proxy_calls_daemon'] or 0,
                'total_proxy_calls_transient': proxy_stats['proxy_calls_transient'] or 0,
                'total_proxy_calls_mcp': proxy_stats['proxy_calls_mcp'] or 0,
                'total_proxy_calls_direct': proxy_stats['proxy_calls_direct'] or 0,
                'total_developer_commands': proxy_stats['developer_commands'] or 0,
                'total_ssrf_blocked': proxy_stats['ssrf_attempts_blocked'] or 0,
                'total_allowlist_violations': proxy_stats['allowlist_violations'] or 0,
                'total_redactions_performed': proxy_stats['response_redactions'] or 0,
                'total_process_verifications_failed': proxy_stats['process_verifications_failed'] or 0,
                'total_production_write_challenges': proxy_stats['production_write_challenges'] or 0,
                'total_interactive_prompts_shown': proxy_stats['interactive_prompts_shown'] or 0,
                'total_interactive_prompts_skipped': proxy_stats['interactive_prompts_skipped'] or 0,
                'total_drift_diffs_detected': proxy_stats['drift_diffs_detected'] or 0,
                'total_log_verifications': proxy_stats['log_chain_verifications'] or 0,
                'total_tampering_alerts': proxy_stats['tampering_detected'] or 0,
                'total_identity_anonymous_calls': proxy_stats['identity_anonymous_calls'] or 0,
                'total_identity_declared_calls': proxy_stats['identity_declared_calls'] or 0,
                'total_identity_issued_calls': proxy_stats['identity_issued_calls'] or 0,
                'total_capability_violations_blocked': proxy_stats['capability_violations_blocked'] or 0,
                'total_process_verifications_passed': proxy_stats['process_verifications_passed'] or 0,
                'total_errors_auth': proxy_stats['errors_auth_count'] or 0,
                'total_errors_keychain': proxy_stats['errors_keychain_count'] or 0,
                'total_errors_secrets': proxy_stats['errors_secrets_count'] or 0,
                'total_errors_network': proxy_stats['errors_network_count'] or 0,
                'total_errors_system': proxy_stats['errors_system_count'] or 0,
                'total_errors_unknown': proxy_stats['errors_unknown_count'] or 0,
                'typos_usage': typos_usage,
            }'''

content = content.replace('''                'total_proxy_calls': proxy_stats['total_calls'] or 0,
                'total_proxy_blocked': proxy_stats['total_blocked'] or 0,
                'total_proxy_redacted': proxy_stats['total_redacted'] or 0,
                'command_usage': command_usage,
                'environment_distribution': env_dist,
                'integration_usage': integration_usage,
            }''', defaults_str)

content += '''\n        from django.core.cache import cache\n        cache.delete(
