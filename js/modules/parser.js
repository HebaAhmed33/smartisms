/**
 * SmartISMS - Configuration Parser & Normalizer Module
 * Parses configuration files and normalizes syntax for rule matching
 */

export class Parser {
    /**
     * Parse and normalize a configuration file
     * @param {string} content - Raw file content
     * @param {string} platform - Detected platform
     * @returns {{lines: string[], normalized: string, sections: Object}}
     */
    parse(content, platform) {
        // Step 1: Split into lines
        const rawLines = content.split(/\r?\n/);

        // Step 2: Remove comments (platform-specific)
        const cleanedLines = rawLines.map(line => this._removeComment(line, platform));

        // Step 3: Trim whitespace
        const trimmedLines = cleanedLines.map(line => line.trim());

        // Step 4: Remove empty lines for analysis (preserve for display)
        const significantLines = trimmedLines.filter(line => line.length > 0);

        // Step 5: Normalize the content
        const normalized = this._normalize(significantLines, platform);

        // Step 6: Extract sections
        const sections = this._extractSections(significantLines, platform);

        return {
            lines: significantLines,
            normalized,
            sections,
            lineCount: rawLines.length,
            significantLineCount: significantLines.length
        };
    }

    /**
     * Remove comments based on platform
     * @private
     */
    _removeComment(line, platform) {
        switch (platform) {
            case 'cisco':
                // Cisco uses ! for comments
                if (line.trim().startsWith('!')) return '';
                return line;
            case 'junos':
                // JunOS uses ## and /* */
                if (line.trim().startsWith('##')) return '';
                return line.replace(/\/\*.*?\*\//g, '');
            case 'linux':
            case 'firewall':
                // Linux/firewall uses #
                return line.replace(/#.*$/, '');
            case 'nginx':
                // Nginx uses #
                return line.replace(/#.*$/, '');
            case 'apache':
                // Apache uses #
                return line.replace(/#.*$/, '');
            default:
                // Generic: try both
                if (line.trim().startsWith('!')) return '';
                return line.replace(/#.*$/, '');
        }
    }

    /**
     * Normalize configuration text for consistent matching
     * @private
     */
    _normalize(lines, platform) {
        let text = lines.join('\n');

        // Normalize whitespace: multiple spaces to single
        text = text.replace(/[ \t]+/g, ' ');

        // Lowercase for case-insensitive matching
        // (keep original for display, this is for the engine)
        return text;
    }

    /**
     * Extract logical sections from the config
     * @private
     */
    _extractSections(lines, platform) {
        const sections = {};
        let currentSection = 'global';
        sections[currentSection] = [];

        for (const line of lines) {
            // Detect section beginnings based on platform
            if (platform === 'cisco') {
                if (line.startsWith('interface ')) {
                    currentSection = line;
                    sections[currentSection] = [];
                } else if (line.startsWith('line ')) {
                    currentSection = line;
                    sections[currentSection] = [];
                } else if (line.startsWith('router ')) {
                    currentSection = line;
                    sections[currentSection] = [];
                }
            } else if (platform === 'nginx' || platform === 'junos') {
                if (line.includes('{')) {
                    currentSection = line.replace('{', '').trim();
                    sections[currentSection] = [];
                } else if (line.includes('}')) {
                    currentSection = 'global';
                }
            } else if (platform === 'apache') {
                if (line.startsWith('<') && !line.startsWith('</')) {
                    currentSection = line;
                    sections[currentSection] = [];
                } else if (line.startsWith('</')) {
                    currentSection = 'global';
                }
            }

            if (!sections[currentSection]) {
                sections[currentSection] = [];
            }
            sections[currentSection].push(line);
        }

        return sections;
    }
}
