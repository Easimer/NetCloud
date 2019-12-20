local p_netcloud = Proto("netcloud", "NetCloud")
local p_netcloud_achievement = Proto("netcloud.achievement", "NetCloud Achievements")
local p_netcloud_login = Proto("netcloud.login", "NetCloud Login")
local p_netcloud_path = Proto("netcloud.path", "NetCloud Generic Path Request")
local p_netcloud_rs = Proto("netcloud.rs", "NetCloud Remote Storage")

local vs_cmds = {
	[0x01] = "CMD_LOGIN",
	[0x02] = "CMD_LOGOUT",
	[0x03] = "CMD_AUTH",
	[0x04] = "CMD_AUTHRES",
	[0x10] = "CMD_WRITE",
	[0x11] = "CMD_READ",
	[0x12] = "CMD_FORGET",
	[0x13] = "CMD_DELETE",
	[0x14] = "CMD_EXISTS",
	[0x15] = "CMD_SIZE",
	[0x16] = "CMD_ACHIEVEMENT",
}

local vs_achi_subcmds = {
	[0x00] = "OP_ACHI_CLEAR",
	[0x01] = "OP_ACHI_GET",
	[0x02] = "OP_ACHI_SET",
	[0x03] = "OP_ACHI_BLKGET",
}

local f_ver = ProtoField.uint8("netcloud.version", "Protocol version", base.DEC)
local f_cmd = ProtoField.uint8("netcloud.cmd", "Packet command", base.HEX, vs_cmds)
local f_flags = ProtoField.uint8("netcloud.flags", "Flags", base.DEC)
local f_len = ProtoField.uint32("netcloud.len", "Packet length", base.DEC)
local f_signature = ProtoField.bytes("netcloud.signature", "Packet signature", base.COLON)
local f_result = ProtoField.uint8("netcloud.result", "Result")
p_netcloud.fields = { f_ver, f_cmd, f_flags, f_len, f_signature, f_result }

local f_achi_cmd = ProtoField.uint8("netcloud.achievement.cmd", "Achievement subcommand", base.HEX, vs_achi_subcmds)
local f_achi_id = ProtoField.string("netcloud.achievement.id", "Achievement identifier")
local f_achi_state = ProtoField.bool("netcloud.achievement.state", "Achievement state")
p_netcloud_achievement.fields = { f_achi_cmd, f_achi_id, f_achi_state }

local f_login_userid = ProtoField.uint64("netcloud.login.user", "User ID", base.DEC)
local f_login_appid = ProtoField.uint64("netcloud.login.app", "App ID", base.DEC)
local f_login_shared = ProtoField.bytes("netcloud.login.shared", "Shared", base.COLON)
local f_login_challenge = ProtoField.bytes("netcloud.login.challenge", "Challenge", base.COLON)
local f_login_answer  = ProtoField.bytes("netcloud.login.answer", "Answer", base.COLON)
local f_login_result  = ProtoField.bool("netcloud.login.result", "Result")
p_netcloud_login.fields = { f_login_userid, f_login_appid, f_login_shared, f_login_challenge, f_login_answer, f_login_result }

local f_path_path = ProtoField.string("netcloud.path.path", "Path")
p_netcloud_path.fields = { f_path_path }

local f_rs_path = ProtoField.string("netcloud.rs.path", "RemoteStorage file path")
local f_rs_contents = ProtoField.bytes("netcloud.rs.contents", "RemoteStorage file contents")
local f_rs_read = ProtoField.int32("netcloud.rs.read", "RemoteStorage number of bytes read")
local f_rs_size = ProtoField.int32("netcloud.rs.size", "RemoteStorage file size")
p_netcloud_rs.fields = { f_rs_path, f_rs_contents, f_rs_read, f_rs_size }

local function dissect_v1_achievement(buf, pkt, tree, srv_to_cli)
	local subtree = tree:add(p_netcloud_achievement, buf)
	subtree:add(f_achi_cmd, buf(0, 1))

	local subcmd = buf(0, 1):uint()

	if subcmd == 0x00 or subcmd == 0x01 or subcmd == 0x02 then
		if srv_to_cli then
			subtree:add(f_achi_state, buf(0, 1))
		else
			local len = buf(1, 4):le_uint()
			subtree:add(f_achi_id, buf(5, len))
		end
	elseif subcmd == 0x03 then
		if srv_to_cli then
			local offset = 1
			while offset < buf:len() do
				local len = buf(offset, 4):le_uint()
				if len ~= 0 then
					print(offset)
					print(len)
					subtree:add(f_achi_id, buf(offset + 4, len))
				else
					break
				end
				offset = offset + 4 + len
			end
		end
	else
	end
end

local function dissect_v1_login(buf, pkt, tree, srv_to_cli)
	local subtree = tree:add(p_netcloud_login, buf)
	subtree:add_le(f_login_userid, buf(0, 8))
	subtree:add_le(f_login_appid, buf(8, 8))
end

local function dissect_v1_auth_chl(buf, pkt, tree)
	local subtree = tree:add(p_netcloud_login, buf)
	subtree:add_le(f_login_shared, buf(0, 64))
	subtree:add_le(f_login_challenge, buf(64, 32))
end

local function dissect_v1_auth_answer(buf, pkt, tree)
	local subtree = tree:add(p_netcloud_login, buf)
	subtree:add_le(f_login_answer, buf(0, 32))
end

local function dissect_v1_auth_result(buf, pkt, tree, srv_to_cli)
	local subtree = tree:add(p_netcloud_login, buf)
	subtree:add(f_login_result, buf(0, 1))
end

local function dissect_v1_auth(buf, pkt, tree, srv_to_cli)
	if srv_to_cli then
		dissect_v1_auth_chl(buf, pkt, tree)
	else
		dissect_v1_auth_answer(buf, pkt, tree)
	end
end

local function dissect_v1_generic_path(buf, pkt, tree)
	local len = buf(0, 4):le_uint()
	local subtree = tree:add(p_netcloud_path, buf)
	subtree:add(f_path_path, buf(4, len))
end

local function dissect_v1_generic_result(buf, pkt, tree)
	tree:add(f_result, buf(0, 1))
end

local function dissect_v1_exists(buf, pkt, tree, srv_to_cli)
	if srv_to_cli then
		dissect_v1_generic_result(buf, pkt, tree)
	else
		dissect_v1_generic_path(buf, pkt, tree)
	end
end

local function dissect_v1_write(buf, pkt, tree, srv_to_cli)
	if srv_to_cli then
		dissect_v1_generic_result(buf, pkt, tree)
	else
		local len_path = buffer(0, 4):le_uint()
		local len_contents = buffer(4, 4):le_uint()
		local filename = buffer(8, len_path)
		local contents = buffer(8 + len_path, len_contents)

		local subtree = tree:add(p_netcloud_rs, buf)
		subtree:add(f_rs_path, filename)
		subtree:add(f_rs_contents, contents)
	end
end

local function dissect_v1_read(buf, pkt, tree, srv_to_cli)
	local subtree = tree:add(p_netcloud_rs, buf)
	if srv_to_cli then
		local rd = buf(0, 4):le_int()
		subtree:add_le(f_rs_read, buf(0, 4))
		if rd ~= -1 then
			subtree:add(f_rs_contents, buf(4, rd))
		end
	else
		local len = buf(4, 4):le_uint()
		subtree:add_le(f_rs_read, buf(0, 4))
		subtree:add(f_rs_path, buf(8, len))
		
	end
end

local function dissect_v1_delete(buf, pkt, tree, srv_to_cli)
	if srv_to_cli then
		dissect_v1_generic_result(buf, pkt, tree)
	else
		dissect_v1_generic_path(buf, pkt, tree)
	end
end

local function dissect_v1_size(buf, pkt, tree, srv_to_cli)
	if srv_to_cli then
		local subtree = tree:add(p_netcloud_rs, buf)
		subtree:add_le(f_rs_size, buf(0, 4))
	else
		dissect_v1_generic_path(buf, pkt, tree)
	end
end

local subdis = {
	[0x01] = dissect_v1_login,
	[0x03] = dissect_v1_auth,
	[0x04] = dissect_v1_auth_result,
	[0x10] = dissect_v1_write,
	[0x11] = dissect_v1_read,
	[0x12] = dissect_v1_delete,
	[0x13] = dissect_v1_delete,
	[0x14] = dissect_v1_exists,
	[0x15] = dissect_v1_size,
	[0x16] = dissect_v1_achievement,
}

local function dissect_v1(buf, pkt, tree)
	local header_size = 8
	local buf_len = buf:len()
	local offset = 0

	while offset + header_size <= buf_len do
		local cmd = buf(offset + 1, 1):uint()
		local packet_size = buf(offset + 4, 4):le_uint()
		local has_signature = (cmd ~= 0x01)

		if has_signature then
			packet_size = packet_size + 32
		end

		if buf_len - offset < packet_size then
			break
		end

		local subtree = tree:add(p_netcloud, buf(offset, packet_size))
		subtree:add(f_ver, buf(offset + 0, 1))
		subtree:add(f_cmd, buf(offset + 1, 1))
		subtree:add(f_flags, buf(offset + 2, 1))
		subtree:add_le(f_len, buf(offset + 4, 4))

		if has_signature then
			subtree:add(f_signature, buf(offset + packet_size - 32, 32))
		end

		local cmd = buf(offset + 1, 1):uint()

		if subdis[cmd] ~= nil then
			local srv_to_cli = pkt.src_port == 12124
			if has_signature then
				subdis[cmd](buf(offset + 8, packet_size - 32 - 8), pkt, subtree, srv_to_cli)
			else
				subdis[cmd](buf(offset + 8, packet_size - 8), pkt, subtree, srv_to_cli)
			end
		end

		offset = offset + packet_size
	end

	if offset ~= buf_len then
		pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
		pkt.desegment_offset = offset
		return DESEGMENT_ONE_MORE_SEGMENT
	end

	return buf_len
end

function p_netcloud.dissector(buf, pkt, tree)
	-- local subtree = tree:add(p_netcloud, buf(0, 1))
	local version = buf(0, 1):uint()

	if version == 1 then
		return dissect_v1(buf, pkt, tree)
	else
		print("Unsupported netcloud version")
		return 0
	end
end

local tcp_encap_table = DissectorTable.get("tcp.port")
tcp_encap_table:add(12124, p_netcloud)