/**
 * Cleanup job - scheduled background task
 */

const fs = require('fs');
const path = require('path');
const _ = require('lodash');

function scheduleCleanup(callback) {
    // Run cleanup every hour
    setInterval(() => {
        performCleanup()
            .then(() => {
                if (callback) callback();
            })
            .catch(err => {
                console.error('Cleanup failed:', err);
            });
    }, 60 * 60 * 1000);

    // Also run on startup
    performCleanup().catch(err => {
        console.error('Initial cleanup failed:', err);
    });
}

async function performCleanup() {
    const logsDir = path.join(__dirname, '../logs');

    try {
        if (!fs.existsSync(logsDir)) {
            return;
        }

        const files = fs.readdirSync(logsDir);

        // Use lodash to process files
        const oldFiles = _.filter(files, file => {
            const filePath = path.join(logsDir, file);
            const stats = fs.statSync(filePath);
            const ageInDays = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24);
            return ageInDays > 7;
        });

        // Delete old files
        _.forEach(oldFiles, file => {
            fs.unlinkSync(path.join(logsDir, file));
        });

        console.log(`Cleaned up ${oldFiles.length} old log files`);
    } catch (error) {
        console.error('Cleanup error:', error);
    }
}

module.exports = {
    scheduleCleanup,
    performCleanup
};
