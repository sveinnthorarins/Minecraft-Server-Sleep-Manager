# Minecraft Server Sleep Manager

This is a Windows console-application designed to manage a Minecraft server, essentially enabling it to be on-demand.

It starts the server when someone tries to connect to it and shuts down the server when nobody is playing on it.

## Q: In what way does it manage the server?

It manages the server by listening to activity on the server's port.

**When the server is up and running**

The app performs an activity check every 30 minutes.
If there are no established connections on the port then there are no players currently playing on the server and thus the server is shut down.

**When the server is not running**

The app listens to activity on the server's port and if someone pings or tries to connect through that port then the server is started. 

> Take note, just pinging the server is enough for it to be started up. Simply opening the multiplayer server list in Minecraft will ping all saved servers in the list to see their status. That ping is enough for the app to start the server.

## Q: How do I set this up for my Minecraft server?

Get the executable from the projects releases or download the source code and build the executable yourself.

Put the executable inside the minecraft server's folder (the folder that contains the server's .jar file and the server.properties file).

Now, for the application to work it needs a few things:

1. A "start.bat" file in the same folder that includes the java command you want to start the server (people may have different start commands since they want different amounts of allocated memory, etc.). When the app starts the server it opens up a new cmd.exe application and runs the start.bat script.

2. RCON needs to be enabled on your server. Do this by changing your server.properties file. Set enable-rcon to true and choose a password for the rcon.password property. The app uses RCON to pass on the command to stop the server.

## Q: Who are you and how can I contact you?

My name is Sveinn and I'm studying Software Engineering at the University of Iceland.

If you have problems with the application you can create an issue on GitHub.

If you want to contact me for other reasons you can add me on Discord: Senz#5171

