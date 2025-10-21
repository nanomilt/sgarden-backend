export const logUserAction = (action, user, data) => {
	// VULNERABILITY: Logging sensitive information
	console.log(`[${new Date().toISOString()}] ${action}`, {
		user: user.username,
		password: user.password, // Never log passwords
		email: user.email,
		data: JSON.stringify(data) // May contain sensitive info
	});
};