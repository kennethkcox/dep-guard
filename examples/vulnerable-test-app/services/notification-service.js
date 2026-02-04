/**
 * Notification service - uses node-notifier
 */

const notifier = require('node-notifier');

async function send(options) {
    const { type, message, recipients } = options;

    // VULNERABLE: node-notifier < 9.0.1 has command injection vulnerability
    return new Promise((resolve, reject) => {
        notifier.notify({
            title: type,
            message: message,
            sound: true,
            wait: false
        }, (err, response) => {
            if (err) {
                reject(err);
            } else {
                resolve({ sent: true, recipients });
            }
        });
    });
}

function sendAlert(message) {
    return send({
        type: 'Alert',
        message,
        recipients: ['admin']
    });
}

module.exports = {
    send,
    sendAlert
};
