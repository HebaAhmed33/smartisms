/**
 * SmartISMS - Validation Engine Module
 * 5-layer validation pipeline that must pass before processing
 */

export class ValidationEngine {
    constructor() {
        this.maxFileSize = 5 * 1024 * 1024; // 5 MB
        this.allowedExtensions = ['conf', 'cfg', 'txt'];
    }

    /**
     * Run all 5 validation layers on a file
     * @param {Object} file - {name, size, content, extension}
     * @returns {{valid: boolean, errors: string[], warnings: string[]}}
     */
    validate(file) {
        const errors = [];
        const warnings = [];

        // Layer 1: Extension validation
        if (!this._validateExtension(file.extension)) {
            errors.push(`Invalid file extension ".${file.extension}". Allowed: .conf, .cfg, .txt`);
        }

        // Layer 2: File size validation
        if (!this._validateSize(file.size)) {
            errors.push(`File size (${(file.size / 1024 / 1024).toFixed(2)} MB) exceeds maximum of 5 MB`);
        }

        // Layer 3: Encoding validation (UTF-8 / ASCII)
        if (!this._validateEncoding(file.content)) {
            errors.push('File contains non UTF-8/ASCII characters. Only text files are accepted.');
        }

        // Layer 4: Text-only content validation
        if (!this._validateTextContent(file.content)) {
            errors.push('File appears to contain binary content. Only text configuration files are accepted.');
        }

        // Layer 5: Content check - should have some meaningful content
        if (file.content.trim().length === 0) {
            errors.push('File is empty. Please upload a valid configuration file.');
        } else if (file.content.trim().split('\n').length < 2) {
            warnings.push('File contains very few lines. Results may be limited.');
        }

        return {
            valid: errors.length === 0,
            errors,
            warnings
        };
    }

    /**
     * Validate all files in batch
     * @param {Array} files
     * @returns {{allValid: boolean, results: Array}}
     */
    validateAll(files) {
        const results = files.map(file => ({
            fileName: file.name,
            ...this.validate(file)
        }));

        return {
            allValid: results.every(r => r.valid),
            results
        };
    }

    /**
     * Layer 1: Extension validation
     * @private
     */
    _validateExtension(extension) {
        return this.allowedExtensions.includes(extension);
    }

    /**
     * Layer 2: File size validation
     * @private
     */
    _validateSize(size) {
        return size <= this.maxFileSize;
    }

    /**
     * Layer 3: Encoding validation
     * Checks for common non-UTF8/ASCII byte patterns
     * @private
     */
    _validateEncoding(content) {
        // Check for null bytes and other non-text control characters
        for (let i = 0; i < content.length; i++) {
            const code = content.charCodeAt(i);
            // Allow common text characters: tab, newline, carriage return, and printable
            if (code === 0) return false; // null byte
            if (code < 8) return false; // non-text control chars
            if (code === 14 || code === 15) return false; // shift in/out
        }
        return true;
    }

    /**
     * Layer 4: Text-only content validation
     * Detects binary content
     * @private
     */
    _validateTextContent(content) {
        // Check ratio of non-printable characters
        let nonPrintable = 0;
        const sampleSize = Math.min(content.length, 8192);

        for (let i = 0; i < sampleSize; i++) {
            const code = content.charCodeAt(i);
            if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
                nonPrintable++;
            }
        }

        // If more than 10% non-printable, likely binary
        return (nonPrintable / sampleSize) < 0.1;
    }
}
