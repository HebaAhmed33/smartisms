/**
 * SmartISMS - Input Handler Module
 * Handles file reading and intake from user uploads
 */

export class InputHandler {
    constructor() {
        this.files = [];
    }

    /**
     * Read uploaded files and return their text content
     * @param {FileList} fileList - Files from input element
     * @returns {Promise<Array<{name, size, content, extension}>>}
     */
    async readFiles(fileList) {
        this.files = [];
        const promises = [];

        for (const file of fileList) {
            promises.push(this._readSingleFile(file));
        }

        this.files = await Promise.all(promises);
        return this.files;
    }

    /**
     * Read a single file
     * @private
     */
    _readSingleFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                resolve({
                    name: file.name,
                    size: file.size,
                    content: e.target.result,
                    extension: this._getExtension(file.name),
                    lastModified: file.lastModified
                });
            };
            reader.onerror = () => reject(new Error(`Failed to read file: ${file.name}`));
            reader.readAsText(file);
        });
    }

    /**
     * Extract file extension
     * @private
     */
    _getExtension(filename) {
        const parts = filename.split('.');
        return parts.length > 1 ? parts.pop().toLowerCase() : '';
    }

    /**
     * Get loaded files
     */
    getFiles() {
        return this.files;
    }

    /**
     * Clear loaded files
     */
    clear() {
        this.files = [];
    }
}
