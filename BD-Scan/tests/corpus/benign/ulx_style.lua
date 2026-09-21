local CATEGORY_NAME = "Utility"
function ulx.cleanup( calling_ply )
    game.CleanUpMap()
    ulx.fancyLogAdmin( calling_ply, "#A cleaned up the map" )
end
local cleanup = ulx.command( CATEGORY_NAME, "ulx cleanup", ulx.cleanup, "!cleanup" )
cleanup:defaultAccess( ULib.ACCESS_ADMIN )

function ulx.setgroup( calling_ply, target_ply, group )
    if not ULib.ucl.groups[ group ] then return end
    target_ply:SetUserGroup( group )
    ucl.addUser( target_ply:SteamID(), group )
end

function ulx.kickall( calling_ply, reason )
    for _, v in ipairs( player.GetAll() ) do
        if v ~= calling_ply then v:Kick( reason ) end
    end
end
