-- Create /var/lib/netcloud/auth.db using this script.

CREATE TABLE user (
	SteamID UNSIGNED BIG INT NOT NULL PRIMARY KEY,
	Key TEXT NOT NULL
);

CREATE TABLE AchievementsEarned (
	AppID UNSIGNED BIG INT NOT NULL,
	AchiID TEXT NOT NULL,
	SteamID UNSIGNED BIG INT NOT NULL REFERENCES user(SteamID),

	CONSTRAINT ACHIEVEMENTEARNED_PK PRIMARY KEY(AppID, AchiID, SteamID)
);

-- To create a new user, insert into the user table the ID and auth key you want, like this:
-- INSERT INTO user (10, "ExampleKey1234");
-- To use these new credentials, append the following to the end of your steam_emu configuration file:
--
-- UserID=100
-- NetCloudKey=ExampleKey1234
--
--
