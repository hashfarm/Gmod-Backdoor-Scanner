-- The shape of Facepunch's own sandbox gamemode: SendLua with a fixed string
-- or a fixed string.format template. Reported at LOW, never CRITICAL.
-- Modelled on garrysmod/gamemodes/sandbox/gamemode/player_extension.lua and
-- lua/includes/modules/cleanup.lua.

function GM:ShowTeam( ply )
	ply:SendLua( "GAMEMODE:ShowTeam()" )
end

function GM:UnfreezeAll( ply, num )
	ply:SendLua( string.format( "GAMEMODE:UnfrozeObjects(%d)", num ) )
end

function GM:NotifyLimit( ply, str )
	ply:SendLua( string.format( "hook.Run('LimitHit',%q)", str ) )
end

function GM:AnnounceCleanup( ply, what )
	ply:SendLua( string.format( "hook.Run('OnCleanup',%q)", what ) )
	BroadcastLua( "hook.Run('CleanupFinished')" )
end
