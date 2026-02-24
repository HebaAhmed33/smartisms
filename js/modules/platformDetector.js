/**
 * SmartISMS - Platform Detection Module
 * Fingerprint-based platform detection using keyword signatures
 */

export class PlatformDetector {
    constructor() {
        this.signatures = {
            cisco: {
                keywords: ['hostname', 'enable secret', 'enable password', 'service password-encryption',
                    'access-list', 'interface GigabitEthernet', 'interface FastEthernet',
                    'line vty', 'line con', 'ip ssh', 'snmp-server', 'aaa new-model',
                    'transport input', 'logging buffered', 'ntp server', 'router ospf',
                    'router bgp', 'ip route'],
                weight: 0,
                label: 'Cisco IOS'
            },
            junos: {
                keywords: ['system {', 'interfaces {', 'protocols {', 'firewall {',
                    'set system', 'set interfaces', 'set protocols', 'root-login',
                    'set security', 'set firewall', 'family inet', 'unit 0'],
                weight: 0,
                label: 'JunOS'
            },
            linux: {
                keywords: ['PermitRootLogin', 'PasswordAuthentication', 'PubkeyAuthentication',
                    'Protocol 2', 'MaxAuthTries', 'ClientAliveInterval',
                    'LoginGraceTime', 'X11Forwarding', 'AllowTcpForwarding',
                    'Subsystem sftp', 'sshd_config', 'UsePAM', 'AllowGroups',
                    'SyslogFacility', 'LogLevel'],
                weight: 0,
                label: 'Linux'
            },
            nginx: {
                keywords: ['worker_processes', 'worker_connections', 'server {', 'listen 80',
                    'listen 443', 'server_name', 'server_tokens', 'location /',
                    'proxy_pass', 'ssl_certificate', 'ssl_protocols', 'nginx',
                    'upstream', 'add_header', 'error_log', 'access_log'],
                weight: 0,
                label: 'Nginx'
            },
            apache: {
                keywords: ['<VirtualHost', 'ServerName', 'ServerAdmin', 'DocumentRoot',
                    'ServerTokens', 'ServerSignature', 'SSLEngine', 'SSLProtocol',
                    'SSLCertificateFile', '<Directory', 'AllowOverride',
                    'ErrorLog', 'CustomLog', 'Header always', 'TraceEnable',
                    'APACHE_LOG_DIR'],
                weight: 0,
                label: 'Apache'
            },
            firewall: {
                keywords: ['iptables', 'firewall-cmd', 'ufw', '-P INPUT', '-P FORWARD',
                    '-P OUTPUT', '-A INPUT', '-A FORWARD', '-j ACCEPT', '-j DROP',
                    '-j LOG', '--dport', '--sport', '-m state', 'chain',
                    'iptables-save', 'log-prefix'],
                weight: 0,
                label: 'Firewall'
            }
        };
    }

    /**
     * Detect platform from file content
     * @param {string} content - File content
     * @returns {{platform: string, label: string, confidence: number, scores: Object}}
     */
    detect(content) {
        const contentLower = content.toLowerCase();
        const scores = {};

        // Score each platform
        for (const [platform, sig] of Object.entries(this.signatures)) {
            let matchCount = 0;
            for (const keyword of sig.keywords) {
                if (contentLower.includes(keyword.toLowerCase())) {
                    matchCount++;
                }
            }
            scores[platform] = {
                matches: matchCount,
                total: sig.keywords.length,
                confidence: sig.keywords.length > 0 ? Math.round((matchCount / sig.keywords.length) * 100) : 0,
                label: sig.label
            };
        }

        // Find best match
        let bestPlatform = 'unknown';
        let bestScore = 0;
        let bestLabel = 'Unknown (Generic Mode)';

        for (const [platform, score] of Object.entries(scores)) {
            if (score.matches > bestScore) {
                bestScore = score.matches;
                bestPlatform = platform;
                bestLabel = score.label;
            }
        }

        // Require minimum confidence threshold
        const confidence = scores[bestPlatform]?.confidence || 0;
        if (confidence < 15) {
            bestPlatform = 'unknown';
            bestLabel = 'Unknown (Generic Mode)';
        }

        return {
            platform: bestPlatform,
            label: bestLabel,
            confidence,
            scores
        };
    }

    /**
     * Detect platforms for multiple files
     * @param {Array} files
     * @returns {Array}
     */
    detectAll(files) {
        return files.map(file => ({
            fileName: file.name,
            ...this.detect(file.content)
        }));
    }
}
