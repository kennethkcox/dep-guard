/**
 * User service - fetches user data
 */

const axios = require('axios');

async function fetchUserData(userId) {
    try {
        // VULNERABLE: axios < 0.21.2 has SSRF vulnerability
        const response = await axios.get(`https://api.example.com/users/${userId}`);
        return response.data;
    } catch (error) {
        // Fallback to mock data
        return {
            id: userId,
            username: 'testuser',
            version: '1.0.0'
        };
    }
}

async function fetchUserProfile(userId) {
    // Another path to axios
    const response = await axios({
        method: 'get',
        url: `https://api.example.com/profiles/${userId}`
    });
    return response.data;
}

module.exports = {
    fetchUserData,
    fetchUserProfile
};
