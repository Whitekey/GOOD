local common = agent.require "agent.platform.linux.common"
local cmd_api = agent.require "agent.platform.linux.cmd_api"
local file_api = agent.require "agent.platform.linux.file_api"
local string_api = agent.require "agent.platform.linux.string_api"
local report_api = agent.require "agent.platform.linux.report_api"
local soft_api = agent.require "agent.platform.linux.soft"
local string_cmd = agent.require "strings"
local cryptographic_api = agent.require "agent.platform.linux.cryptographic_api"
local shell_diff_api = agent.require "agent.rootkit.linux.chk_shell_diff"
local execute_shell = common.execute_shell
local curl = agent.require "curl"
agent.load "rex_pcre"
local rex = rex_pcre
local start_time
local time_out
local time_out_flag = false
local json_table
local pack_dirs
local chk_cmd_ret = {
    --chk_cmd_ret来源于chk_cmd的结果
    --有可能chk_cmd因为异常场景直接return
    --那样的话chk_cmd_ret就会是空table
    --后面shell_diff取problem_cmd就会得到nil
    --ipairs遍历nil会报错。
    ["problem_cmd"] = {}
}

--暂存软件包完整性检查中的RPM检查结果
local chk_rpm_res = {}
--暂存软件包完整性检查中的DPKG检查结果
local chk_dpkg_res = {}

if debug_on then
    json_str = [[
    {
        "args": {
            "package_integrity": {
                "dirs": [
                    "/usr/local/sbin/",
                    "/usr/local/bin/",
                    "/usr/bin/"
                ],
                "softs": [
                    "openssh",
                    "bash",
                    "cmake"
                ]
            },
            "check_bootkit": {},
            "check_rootkit": [
            {
                "name": "chk_known_rootkit"
            },
            {
                "name": "chk_load_so"
            },
            {
                "name": "chk_cmd"
            },
            {
                "name": "chk_lack_module"
            },
            {
                "name": "chk_malicious_module"
            },
            {
                "name": "chk_proc_rename"
            },
            {
                "name": "chk_shell_diff",
                "cmd": [
                    "ls",
                    "mount",
                    "w",
                    "who",
                    "last",
                    "ifconfig",
                    "ss",
                    "netstat",
                    "crontab",
                    "ps"
                ],
                "ls_path": [
                    "/usr/bin/",
                    "/bin/",
                    "/root",
                    "/home"
                ]
            }],
        "timeout": 1800
    }}
]]
end

--------Bootkit实现代码--------
local function bin2hex(s)
  s = string.gsub(s,"(.)", function (x) return string.format("%02x", string.byte(x)) end)
  return s
end

local function get_grub_version()
  local exitcode, output = execute_shell("grub-install --version")

  if exitcode ~= 0 then
    exitcode, output = execute_shell("grub2-install --version")
  end

  if exitcode == 0 and output ~= "" then
    output = string.gsub(output, '[()\n]', '')
    local _, ends = string.find(output, 'GRUB ')

    if ends then
      return string.sub(output, ends + 1)
    end
  else
    return nil
  end
end

-- MBR主引导记录
local function get_boot_mbr()
    local function get_mbr(dev)
        local mbr = ""
        local dev_line_fd = io.open(dev)
        if dev_line_fd then
            local maybe_mbr = dev_line_fd:read(512) or ""
            if (string.byte(maybe_mbr, 0x1FF) == 0x55) and (string.byte(maybe_mbr, 0x200) == 0xAA) then
                mbr = maybe_mbr
            end
            dev_line_fd:close()
        end
        return mbr
    end

    local function chk_vaild_mbr( mbr )
        --https://en.wikipedia.org/wiki/Master_boot_record#PTE
        --过滤规则： 1、mbr共512字节，第一个字节不能是00
        --           2、mbr从447到510是分区信息,每16位为一个分区
        --              447、463、479、495分别为4个分区的各自的第一位，不可以同时为0
        -- by binbin.li@qingteng.cn  2017/08/14
        if not mbr or mbr == "" then
            return false
        end
        --判断启动代码区有效
        if string.byte(tostring(mbr), 0x001) == 0x00 then
            return false
        end
        --判断分区代码区有效
        if string.byte(tostring(mbr), 0x1bf) == 0x00
            and string.byte(tostring(mbr), 0x1cf) == 0x00
            and string.byte(tostring(mbr), 0x1df) == 0x00
            and string.byte(tostring(mbr), 0x1ef) == 0x00 then
            return false
        end
        --4个分区是否可以启动进行检测，Bootable flag 是80
        if string.byte(tostring(mbr), 0x1bf) ~= 0x80
            and string.byte(tostring(mbr), 0x1cf) ~= 0x80
            and string.byte(tostring(mbr), 0x1df) ~= 0x80
            and string.byte(tostring(mbr), 0x1ef) ~= 0x80 then
            return false
        end
        local tmp_mbr = bin2hex(mbr)
        local zero_num = 0
        for i = 1, 446, 1 do
            if string.sub(tmp_mbr, i, i) == "0" then
                zero_num = zero_num + 1
            end
            if zero_num > 200 then
                return false
            end
        end
        return true
    end

    local result = {}
    local count = 0
    local mtab_tb = file_api.read_file_content_l("/etc/mtab")
    for _, line in pairs(mtab_tb) do
        local line_array = string_api.split(line)
        if #line_array == 6 then
            local dev_line = line_array[1]
            if string.match(dev_line, "^/dev/") and not string.match(dev_line, "^/dev/sr")
                and not string.match(dev_line, [[/loop%d+$]]) then
                local mbr = get_mbr(dev_line)
                if chk_vaild_mbr(mbr) then
                    agent.info_log("device : " .. dev_line .. " has mbr!!")
                    result[dev_line] = mbr
                    count = count + 1
                end
                local dev = tostring(string.gsub(dev_line, "%d+$", ""))
                if not result[dev] then
                    local mbr = get_mbr(dev)
                    if chk_vaild_mbr(mbr) then
                        agent.info_log("device : " .. dev .. " has mbr!!")
                        result[dev] = mbr
                        count = count + 1
                    end
                end
            end
        end
    end
    --去重处理
    if count > 1 then
        agent.info_log("the mbr device num more than one, then duplicate removal ...")
        local tmp_result_1 = {}
        local tmp_result_2 = {}
        for k, tmp_mbr in pairs(result) do
            tmp_result_1[bin2hex(tmp_mbr)] = k
        end
        count = 0
        for _, v in pairs(tmp_result_1) do
            count = count + 1
            tmp_result_2[v] = result[v]
            agent.info_log("after duplicate removed, device " .. tostring(v) .. " has mbr!!")
        end
        result = tmp_result_2
    end
    return result, count
end

local function get_grub_mbr()
  local res = ""
  local mbr_path = {"/usr/lib/grub/i386-pc/boot.img",
                    "/usr/share/grub/i386-redhat/stage1",
                    "/usr/share/grub/i386-pc/stage1",
                    "/usr/share/grub/x86_64-redhat/stage1",
                    "/usr/share/grub/x86_64-unknown/stage1"}
  for _, filename in ipairs(mbr_path) do
    local f = io.open(filename)
    if f then
      res = f:read(512)
      f:close()
      break
    end
  end

  return res
end

local function compare_mbr(version, boot_mbr, grub_mbr)
    if version == "" then
        return 2, "get grub version null"
    elseif boot_mbr == "" then
        return 3, "get boot_mbr null"
    elseif grub_mbr == "" then
        return 4, "get grub_mbr null"
    end

    if string.sub(version, 1, 4) == '0.97' then
        if string.sub(boot_mbr, 1, 3) == string.sub(grub_mbr, 1, 3) and
            string.sub(boot_mbr, 0x4B, 0x4B) == string.sub(grub_mbr, 0x4B, 0x4B) and
            (string.sub(boot_mbr, 0x4C, 0x4D) == string.sub(grub_mbr, 0x4C, 0x4D) or
            (string.byte(boot_mbr, 0x4C) == 0x90 and string.byte(boot_mbr, 0x4D) == 0x90)) and
            string.sub(boot_mbr, 0x4E, 0x1A5) == string.sub(grub_mbr, 0x4E, 0x1A5) then
            return 0
        else
            return 1, "0.97 version compare failed"
        end
    elseif string.sub(version, 1, 4) == '1.99' or string.sub(version, 1, 3) == '2.0' then
        if string.sub(boot_mbr, 1, 3) == string.sub(grub_mbr, 1, 3) and
            string.sub(boot_mbr, 0x66, 0x66) == string.sub(grub_mbr, 0x66, 0x66) and
            (string.sub(boot_mbr, 0x67, 0x68) == string.sub(grub_mbr, 0x67, 0x68) or
            (string.byte(boot_mbr, 0x67) == 0x90 and string.byte(boot_mbr, 0x68) == 0x90)) and
            string.sub(boot_mbr, 0x69, 0x1A5) == string.sub(grub_mbr, 0x69, 0x1A5) then
            return 0
        else
            return 1, "1.99 or 2.0 version compare failed"
        end
    else
        return 5, "unknow the grub version"
    end
end

local function bootkit_calc_check_result(detail_data)
    local msg = ""
    local check_result = {
        ["msg_ver"] = "bootkit 1.0.0",
        ["com_id"] = detail_data["com_id"],
        ["pcid"] = detail_data["pcid"],
        ["ts"] = detail_data["ts"],
        ["dist_ver"] = detail_data["dist_ver"],
        ["grub_ver"] = detail_data["grub_ver"],
        ["ret_code"] = -1
    }

    check_result["ret_code"], msg = compare_mbr(detail_data["grub_ver"], detail_data["boot_mbr"], detail_data["grub_mbr"])
    if check_result["ret_code"] ~= 0 then
        agent.error_log("[BACK_DIAG]-[bootkit_calc_check_result]: compare_mbr failed, " .. tostring(msg))
        check_result["msg_ver"] = check_result["msg_ver"] .. "," .. tostring(msg)
    end
    return check_result
end

local function bootkit_calc_detail_data(boot_mbr, grub_ver, grub_mbr)
  local result = {}

  result["msg_ver"] = "bootkit 1.0.0"
  result["ts"] = os.time()

  result["grub_ver"] = grub_ver or ""
  result["boot_mbr"] = boot_mbr or ""
  result["grub_mbr"] = grub_mbr or ""

  local link = agent.get_link_info()
  result["com_id"] = link["com_id"]
  result["pcid"] = link["pcid"]

  local sysinfo = cjson.decode(agent.get_sysinfo())
  result["dist_ver"] = string.gsub(sysinfo["os_info"]["dist_ver"], "\n", "")
  result["kernel_ver"] = sysinfo["os_info"]["kernel_ver"]
  result["is_64bit"] = sysinfo["os_info"]["is_64bit"]
  result["vmlinuz_md5"] = agent.get_file_md5("/boot/vmlinuz-" .. result["kernel_ver"]) or ""
  result["initfs_md5"] = agent.get_file_md5("/boot/initrd-" .. result["kernel_ver"] .. '.img') or
                      agent.get_file_md5("/boot/initrd.img-" .. result["kernel_ver"]) or
                      agent.get_file_md5("/boot/initramfs-" .. result["kernel_ver"] .. '.img') or ""

  return result
end

--[[
    {
        "ret_msg": {
            "com_id": "a85acd72128679169a0e",
            "ts": 1533609725,
            "boot_mbr": "eb489...55aa",
            "pcid": "1cc64150a44d57c4",
            "dist_ver": "CentOS release 6.9 (Final)",
            "grub_mbr": "eb489...55aa",
            "grub_ver": "0.97",
            "single_mbr": true,
            "msg_ver": "bootkit 1.0.0"
        },
        "ret_code": 0 // 0, MBR相同
                      // 1, MBR不相同
                      // 2, 获取grub版本失败
                      // 3, 获取扇区MBR失败
                      // 4, 获取grub MBR失败
                      // 5, grub版本不支持
    }
]]--
local function bootkit_message()
    local detail_data = {}
    local check_result = {}
    local grub_version = get_grub_version() or ""
    local grub_mbr = get_grub_mbr() or ""

    local boot_mbr_tb, mbr_num = get_boot_mbr()
    if mbr_num == 0 or mbr_num == 1 then
        --获取mbr失败或者系统上只存在一处mbr
        local boot_mbr = ""
        for _, v in pairs(boot_mbr_tb) do
            boot_mbr = v
        end
        detail_data = bootkit_calc_detail_data(boot_mbr, grub_version, grub_mbr)
        check_result = bootkit_calc_check_result(detail_data)
        check_result["single_mbr"] = true
        check_result["boot_mbr"] = bin2hex(detail_data["boot_mbr"])
        check_result["grub_mbr"] = bin2hex(detail_data["grub_mbr"])
    elseif mbr_num >= 2 then
        --系统上存在多处mbr
        for k, mbr in pairs(boot_mbr_tb) do
            boot_mbr_tb[k] = bin2hex(mbr)
        end
        detail_data = bootkit_calc_detail_data(cjson.encode(boot_mbr_tb), grub_version, grub_mbr)
        check_result = bootkit_calc_check_result(detail_data)
        check_result["ret_code"] = 1
        check_result["single_mbr"] = false
        check_result["grub_mbr"] = bin2hex(detail_data["grub_mbr"])
        check_result["boot_mbr"] = cjson.encode(boot_mbr_tb)
    end

    --上报消息数据
    local ret_table = {}
    ret_table["ret_code"] = check_result["ret_code"]
    check_result["ret_code"] = nil
    ret_table["ret_msg"] = check_result
    return ret_table
end
--------包完整性实现代码--------
local function is_prelink_file(file_name)
    local file_content = file_api.read_file_content(file_name)
    if string.find(file_content, ".gnu.prelink", 1, true) then
        return true
    else
        return false
    end
end

local function get_digest(file_name, hash_num)
    local digest = ""
    local is_prelink = is_prelink_file(file_name)

    if hash_num == 32 then
        if is_prelink then
            local ret, msg = common.execute_shell("prelink -y --md5 " .. file_name)
            if ret == 0 and msg then
                local tmp = common.split(msg, " ")
                digest = tmp[1]
            end
        else
            digest = agent.get_file_md5(file_name)
        end
    elseif hash_num == 64 then
        if is_prelink then
            local path = agent.get_app_path() .. "/data/tmp_check_package"
            local ret, msg = common.execute_shell("prelink -u " .. file_name .. " -o " .. path)
            if ret == 0 then
                digest = cryptographic_api.sha256(path, true)
            end
        else
            digest = cryptographic_api.sha256(file_name, true)
        end
    end

    agent.debug_log(file_name .. " : " .. tostring(digest))

    if digest == "" then
        return nil
    else
        return digest
    end
end

local function is_in_dirs(file_name)
    for _,v in ipairs(pack_dirs) do
        if string.match(file_name, "^" .. v .. [[/?[^%s/]+$]]) then
            return true
        end
    end
    return false
end

local function check_digest(file_name, original_digest, hash_num)
    local ret_file_attr = {}
    local binary_digest = ""

    local file_attr = lfs.symlinkattributes(file_name)
    if not string.match(original_digest, "^0+$") and file_attr and file_attr.mode == "file" and common.is_elf(file_name) and is_in_dirs(file_name) then
        binary_digest = get_digest(file_name, hash_num)
        if binary_digest and binary_digest ~= original_digest then
            ret_file_attr.file_name = file_name
            ret_file_attr.file_owner = common.get_user(file_attr.uid) or ""
            ret_file_attr.file_group = common.get_group(file_attr.gid) or ""
            ret_file_attr.access_time = tonumber(file_attr.access)
            ret_file_attr.change_time = tonumber(file_attr.change)
            ret_file_attr.modify_time = tonumber(file_attr.modification)
            ret_file_attr.permissions = file_attr.permissions
            ret_file_attr.package_hash = original_digest
            ret_file_attr.file_hash = binary_digest
            ret_file_attr.file_md5 = agent.get_file_md5(file_name)
            ret_file_attr.file_size = file_attr.size
            ret_file_attr.file_sha1 = cryptographic_api.sha1(file_name, true) or ""
            ret_file_attr.file_sha256 = cryptographic_api.sha256(file_name, true) or ""
        end
    end

    return ret_file_attr, binary_digest
end

local function check_rpm_package(package_name)
    local modify_files = {}
    local file_digests = {}
    local file_num = 0
    local ret, msg = common.execute_shell_l("rpm -ql " .. tostring(package_name) .. " --dump")
    agent.debug_log("software_package_integrity: rpm -ql " .. tostring(package_name) .. " --dump " .. ret)
    if ret == 0 and msg then
        for _, line in ipairs(msg) do
            if (start_time + time_out) < os.time() then
                time_out_flag = true
                break
            end
            local file_name, digest = string.match(line, [[^(%S+) %S+ %S+ (%w+)]])
            if file_name and digest and is_in_dirs(file_name) then
                local hash_num = string.len(digest)
                local file_attr, real_digest = check_digest(file_name, digest, hash_num)
                if next(file_attr) then
                    if file_digests[file_name] == nil then
                        table.insert(modify_files, file_attr)
                        file_digests[file_name] = 0
                    end
                else
                    if file_digests[file_name] == 0 then
                        for i = 1, #modify_files do
                            if modify_files[i] and modify_files[i].file_name == file_name then
                                table.remove(modify_files, i)
                            end
                        end
                    end
                    file_digests[file_name] = 1
                end
            end

            file_num = file_num + 1
            if file_num == 3000 then
                file_num = 0
                agent.gc()
            end
        end
    else
        agent.info_log("[BACK_DIAG]-[check_rpm_package]-get package (" .. tostring(package_name) .. ") info fail: " .. tostring(msg))
    end
    return modify_files
end

local function check_rpm_binary(package_name, real_file)
    local modify_files = {}
    local find_match = false
    local ret, msg = common.execute_shell_l("rpm -ql " .. tostring(package_name) .. " --dump")
    agent.debug_log("software_package_integrity: rpm -ql " .. tostring(package_name) .. " --dump " .. ret)
    if ret == 0 and msg then
        for _, line in ipairs(msg) do
            if (start_time + time_out) < os.time() then
                time_out_flag = true
                break
            end
            local file_name, digest = string.match(line, [[^(%S+) %S+ %S+ (%w+)]])
            if file_name == real_file and digest and is_in_dirs(file_name) then
                local file_attr, real_digest = check_digest(file_name, digest, string.len(digest))
                if next(file_attr) then
                    table.insert(modify_files, file_attr)
                else
                    find_match = true
                    break
                end
            end
        end
    else
        agent.info_log("[check_rpm] get package (" .. tostring(package_name) .. ") info fail: " .. tostring(msg))
    end
    if find_match then
        modify_files = {}
    end
    return modify_files
end

local function check_rpm()
    local result = {}
    local modify_files = {}

    for _,package_name in ipairs(json_table.args.package_integrity.softs) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end
        local package_modify_files = check_rpm_package(package_name)
        for _, package_file in ipairs(package_modify_files) do
            table.insert(modify_files, package_file)
        end
    end

    for _, file_attr in ipairs(modify_files) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end
        local file_name = file_attr.file_name
        local one_danger = {}
        one_danger["file_name"] = file_name
        one_danger["file_size"] = file_attr.file_size
        one_danger["file_owner"] = file_attr.file_owner
        one_danger["file_group"] = file_attr.file_group
        one_danger["file_permission"] = file_attr.permissions
        one_danger["file_hash"] = file_attr.file_hash
        one_danger["package_hash"] = file_attr.package_hash
        one_danger["access_time"] = file_attr.access_time
        one_danger["change_time"] = file_attr.change_time
        one_danger["modify_time"] = file_attr.modify_time
        one_danger["file_md5"] = file_attr.file_md5
        one_danger["file_sha1"] = file_attr.file_sha1
        one_danger["file_sha256"] = file_attr.file_sha256
        local ret_tmp, msg_tmp = common.execute_shell_l("rpm -qf " .. tostring(file_name))
        if ret_tmp == 0 and msg_tmp then
            local value = {}
            if chk_rpm_res[#chk_rpm_res] and chk_rpm_res[#chk_rpm_res].package_full_name == msg_tmp[1] then
                one_danger["package_name"] = chk_rpm_res[#chk_rpm_res].package_name
                one_danger["package_version"] = chk_rpm_res[#chk_rpm_res].package_version
                one_danger["package_full_name"] = chk_rpm_res[#chk_rpm_res].package_full_name
                table.insert(chk_rpm_res[#chk_rpm_res].files, file_attr)
            else
                one_danger["package_full_name"] = msg_tmp[1]
                value.package_full_name = msg_tmp[1]
                local cmd = "rpm -qf " .. tostring(file_name) .. [[ --qf '%{N}\n%{V}\n']]
                ret_tmp, msg_tmp = common.execute_shell_l(cmd)
                if  ret_tmp == 0 and msg_tmp then
                    value.package_name = msg_tmp[1]
                    value.package_version = msg_tmp[2]
                    value.files = {}
                    table.insert(value.files, file_attr)
                    table.insert(chk_rpm_res, value)
                    one_danger["package_name"] = msg_tmp[1]
                    one_danger["package_version"] = msg_tmp[2]
                end
            end
        end
        table.insert(result, one_danger)
    end

    return result
end

local dpkg_md5sum_files
local function load_dpkg_sums_if_need()
    if dpkg_md5sum_files == nil then
        dpkg_md5sum_files = {}
        for name, _ in lfs.dir("/var/lib/dpkg/info/") do
            if name ~= "." and name ~= ".." and string.sub(name, -8, -1) == ".md5sums" then
                table.insert(dpkg_md5sum_files, "/var/lib/dpkg/info/".. tostring(name))
            end
        end
    end
end

local function check_dpkg_package(package_name)
    local files = {}
    load_dpkg_sums_if_need()
    for _, full_name in ipairs(dpkg_md5sum_files) do
        if string.find(full_name, package_name, 1, true) then
            local f = io.open(full_name)
            if f then
                for line in f:lines() do
                    local md5, file_name = string.match(line, [[(%S+)%s+(%S+)]])
                    if md5 and file_name then
                        if string.sub(file_name, 1, 1) ~= "/" then
                            file_name = "/" .. tostring(file_name)
                        end
                        local file_attr = check_digest(file_name, md5, 32)
                        if next(file_attr) then
                            table.insert(files, file_attr)
                        end
                    end
                end
                io.close(f)
            end
        end
    end

    return files
end

local function check_dpkg_binary(package_name, real_file)
    local files = {}
    load_dpkg_sums_if_need()
    for _, full_name in ipairs(dpkg_md5sum_files) do
        if string.find(full_name, package_name, 1, true) then
            local f = io.open(full_name)
            if f then
                for line in f:lines() do
                    local md5, file_name = string.match(line, [[(%S+)%s+(%S+)]])
                    if string.sub(file_name, 1, 1) ~= "/" then
                        file_name = "/" .. tostring(file_name)
                    end
                    if md5 and file_name == real_file then
                        local file_attr = check_digest(file_name, md5, 32)
                        if next(file_attr) then
                            table.insert(files, file_attr)
                        end
                        break
                    end
                end
                io.close(f)
            end
            break
        end
    end
    return files
end

local function check_dpkg()
    local result = {}

    for _, package_name in ipairs(json_table.args.package_integrity.softs) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end
        local ret, msg = common.execute_shell_l([[dpkg -l ]] .. tostring(package_name) .. [[ | grep "^ii" | awk '{print $2, $3, $4}']])

        if ret == 0 and msg then
            for _, v in ipairs(msg) do
                if (start_time + time_out) < os.time() then
                    time_out_flag = true
                    break
                end
                local pack_info = common.split(v, ' ')
                if next(pack_info) then
                    local files = check_dpkg_package(pack_info[1])
                    if next(files) then
                        local value = {}
                        value.files = files
                        value.package_full_name = tostring(pack_info[1]) .. "_" .. tostring(pack_info[2]) .. "_" .. tostring(pack_info[3])
                        value.package_name = pack_info[1]
                        value.package_version = pack_info[2]
                        table.insert(chk_dpkg_res, value)
                        for _, file_attributes in ipairs(files) do
                            local one_danger = {}
                            one_danger["file_name"] = file_attributes["file_name"]
                            one_danger["file_size"] = file_attributes["file_size"]
                            one_danger["file_owner"] = file_attributes["file_owner"]
                            one_danger["file_group"] = file_attributes["file_group"]
                            one_danger["file_permission"] = file_attributes["permissions"]
                            one_danger["access_time"] = file_attributes["access_time"]
                            one_danger["change_time"] = file_attributes["change_time"]
                            one_danger["modify_time"] = file_attributes["modify_time"]
                            one_danger["file_md5"] = file_attributes["file_md5"]
                            one_danger["file_sha1"] = file_attributes["file_sha1"]
                            one_danger["file_sha256"] = file_attributes["file_sha256"]
                            one_danger["file_hash"] = file_attributes["file_hash"]
                            one_danger["package_hash"] = file_attributes["package_hash"]
                            one_danger["package_name"] = pack_info[1]
                            one_danger["package_version"] = pack_info[2]
                            one_danger["package_full_name"] = value.package_full_name
                            table.insert(result, one_danger)
                        end
                    end
                end
            end
        else
            agent.error_log("[BACK_DIAG]-[check_dpkg]-get package (" .. tostring(package_name) .. ") info fail: " .. tostring(msg))
        end
    end

    return result
end

--[[
"package_integrity": {
        "ret_msg": {
            "rpm": [],
            "dpkg": [
                {
                    "package_full_name": "cmake_3.5.1-1ubuntu3_amd64",
                    "package_hash": "fb38ba1d24ea6237c9e7400a5f606c0e",
                    "file_name": "\/usr\/bin\/cmake",
                    "file_md5": "f3b92d795c9ee0725c160680acd084d9",
                    "package_name": "cmake",
                    "access_time": 1533630291,
                    "package_version": "3.5.1-1ubuntu3",
                    "file_hash": "f3b92d795c9ee0725c160680acd084d9",
                    "change_time": 1533630288,
                    "file_size": 126584,
                    "modify_time": 1533630288
                }
            ]
        },
        "ret_code": 1
    }
]]--
local function package_message()
    local result = {}
    result["rpm"] = {}
    result["dpkg"] = {}
    local ret_table = {}
    ret_table["ret_code"] = 0

    if json_table.args.package_integrity.dirs then
        pack_dirs = json_table.args.package_integrity.dirs
    else
        pack_dirs = {}
    end

    if json_table.args.package_integrity.softs then
        if soft_api.get_rpm_flag() then
            result["rpm"] = check_rpm()
            if #result["rpm"] > 0 then
                ret_table["ret_code"] = 1
            end
        end
        if soft_api.get_dpkg_flag() then
            result["dpkg"] = check_dpkg()
            if #result["dpkg"] > 0 then
                ret_table["ret_code"] = 1
            end
        end
    end

    agent.gc()
    ret_table["ret_msg"] = result
    return ret_table
end
--------Rootkit实现代码--------

------chk_known_rootkit实现------
local function calc_ksyms_path()
    cjson.encode_empty_table_as_object(false)

    local ksyms_path = "/proc/ksyms"
    if file_api.file_exists(ksyms_path) then
        agent.info_log("[BACK_DIAG]-[calc_ksyms_path]-the ksyms file is /proc/ksyms")
        return 0, ksyms_path
    end

    ksyms_path = "/proc/kallsyms"
    if file_api.file_exists(ksyms_path) then
        agent.info_log("[BACK_DIAG]-[calc_ksyms_path]-the ksyms file is /proc/kallsyms")
        return 0, ksyms_path
    end

    return -1, nil
end

local function do_check_known_rootkit(rule_list, ksyms_file)
    local result = {}

    for _, v in pairs(cjson.decode(rule_list)) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end
        if type(v) == 'table' then
            for check_type, value in pairs(v) do
                if (start_time + time_out) < os.time() then
                    time_out_flag = true
                    break
                end
                if check_type == "files" then
                    for _, file_path in pairs(value) do
                        local file_attributes = lfs.attributes(file_path)
                        if file_attributes ~= nil and file_attributes["mode"] ~= "directory" then
                            local one_danger = {}
                            one_danger["extra_info"] = ""
                            one_danger["check_type"] = check_type
                            one_danger["rootkit_name"] = v.rootkit_name
                            one_danger["file_name"] = file_path
                            one_danger["file_size"] = file_attributes["size"]
                            one_danger["file_owner"] = common.get_user(file_attributes["uid"]) or ""
                            one_danger["file_group"] = common.get_group(file_attributes["gid"]) or ""
                            one_danger["file_permission"] = file_attributes["permissions"]
                            one_danger["access_time"] = file_attributes["access"]
                            one_danger["change_time"] = file_attributes["change"]
                            one_danger["modify_time"] = file_attributes["modification"]
                            one_danger["file_md5"] = agent.get_file_md5(file_path) or ""
                            one_danger["file_sha1"] = cryptographic_api.sha1(file_path, true) or ""
                            one_danger["file_sha256"] = cryptographic_api.sha256(file_path, true) or ""
                            table.insert(result, one_danger)
                        end
                    end
                elseif check_type == "dirs" then
                    for _, dir_path in pairs(value) do
                        local file_attributes = lfs.attributes(dir_path)
                        if file_attributes ~= nil and file_attributes["mode"] == "directory" then
                            local one_danger = {}
                            one_danger["extra_info"] = ""
                            one_danger["check_type"] = check_type
                            one_danger["rootkit_name"] = v.rootkit_name
                            one_danger["file_name"] = dir_path
                            one_danger["file_size"] = file_attributes["size"]
                            one_danger["file_owner"] = common.get_user(file_attributes["uid"]) or ""
                            one_danger["file_group"] = common.get_group(file_attributes["gid"]) or ""
                            one_danger["file_permission"] = file_attributes["permissions"]
                            one_danger["access_time"] = file_attributes["access"]
                            one_danger["change_time"] = file_attributes["change"]
                            one_danger["modify_time"] = file_attributes["modification"]
                            one_danger["file_md5"] = ""
                            one_danger["file_sha1"] = ""
                            one_danger["file_sha256"] = ""
                            table.insert(result, one_danger)
                        end
                    end
                elseif check_type == "ksyms" then
                    if file_api.file_exists(tostring(ksyms_file)) then
                        local ksyms_func = {}
                        for _, ksyms_value in pairs(value) do
                            if file_api.find_string_file(ksyms_file, " " .. ksyms_value) ~= nil then
                                table.insert(ksyms_func, ksyms_value)
                            end
                        end
                        if #ksyms_func > 0 then
                            local file_attributes = lfs.attributes(ksyms_file)
                            if type(file_attributes) == "table" then
                                local one_danger = {}
                                one_danger["extra_info"] = cjson.encode(ksyms_func)
                                one_danger["check_type"] = check_type
                                one_danger["rootkit_name"] = v.rootkit_name
                                one_danger["file_name"] = ksyms_file
                                one_danger["file_size"] = file_attributes["size"]
                                one_danger["file_owner"] = common.get_user(file_attributes["uid"]) or ""
                                one_danger["file_group"] = common.get_group(file_attributes["gid"]) or ""
                                one_danger["file_permission"] = file_attributes["permissions"]
                                one_danger["access_time"] = file_attributes["access"]
                                one_danger["change_time"] = file_attributes["change"]
                                one_danger["modify_time"] = file_attributes["modification"]
                                one_danger["file_md5"] = agent.get_file_md5(ksyms_file) or ""
                                one_danger["file_sha1"] = cryptographic_api.sha1(ksyms_file, true) or ""
                                one_danger["file_sha256"] = cryptographic_api.sha256(ksyms_file, true) or ""
                                table.insert(result, one_danger)
                            end
                        end
                    end
                end
            end
        end
    end

    if #result == 0 then
        return 0, result
    else
        return 1, result
    end
end

--[[
{
    "ret_code": 1,
    "ret_msg": [
        {
            "extra_info": "",
            "check_type": "files",
            "access_time": 1533608647,
            "rootkit_name": "QingJing Test",
            "modify_time": 1521128846,
            "file_md5": "e6646a582e5f34a54cd76120db604374",
            "file_name": "\/etc\/passwd",
            "file_size": 1867,
            "change_time": 1521128846
        },
        {
            "extra_info": "[\"dm_suspended_md\"]",
            "check_type": "ksyms",
            "access_time": 1533611515,
            "rootkit_name": "QingJing Test",
            "modify_time": 1533611515,
            "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
            "file_name": "\/proc\/kallsyms",
            "file_size": 0,
            "change_time": 1533611515
        },
        {
            "extra_info": "",
            "check_type": "dirs",
            "access_time": 1533609551,
            "rootkit_name": "QingJing Test",
            "modify_time": 1533609550,
            "file_md5": "",
            "file_name": "\/home\/bert",
            "file_size": 4096,
            "change_time": 1533609550
        }
    ],
    "check_type": "chk_known_rootkit"
},
--]]
local function chk_known_rootkit()
    local result = {}
    result["check_type"] = "chk_known_rootkit"
    result["ret_code"] = 0
    result["ret_msg"] = {}

    local data_code, data_json = agent.get_data_obj_item("script", "data", "agent.collectinfo.linux.rootkit_known_rootkit_data", "content", true, true)
    if data_code ~= true then
        result["ret_code"] = 2
        agent.error_log("[BACK_DIAG]-[chk_known_rootkit]-oops, read rootkit data error!!!")
        return result
    end

    local ksyms_code, ksyms_file = calc_ksyms_path()
    if ksyms_code ~= 0 then
        result["ret_code"] = 3
        agent.error_log("[BACK_DIAG]-[chk_known_rootkit]-oops, ksyms file not found!!!")
        return result
    end

    local check_code, check_data = do_check_known_rootkit(data_json, ksyms_file)
    if check_code ~= 0 then
        result["ret_code"] = 1
        result["ret_msg"] = check_data
    end
    return result
end

------chk_load_so实现------
local function get_path_env()
    local temp_table = {
        "/sbin",
        "/usr/sbin",
        "/lib",
        "/usr/lib",
        "/usr/libexec",
        "."
    }
    local cmd_map = {}
    local path_code, path_tb = common.execute_login_shell_l("echo $PATH")
    if path_code ~= 0 or type(path_tb) ~= "table" or #path_tb == 0 then
        return false, {}
    end
    local cmd_table = string_api.split(path_tb[1], ":")
    for _, v in pairs(cmd_table) do
        cmd_map[v] = true
    end
    for _, v in pairs(temp_table) do
        if cmd_map[v] == nil then
            table.insert(cmd_table, v)
        end
    end
    return true, cmd_table
end


local function check_so_in_blacklist(ld_msg_tb, malicious_so_data)
    if type(ld_msg_tb) ~= "table" or type(malicious_so_data) ~= "string" then
        return {}
    end

    local result = {}
    local ld_lib_tb = {}
    for _, one_msg in ipairs(ld_msg_tb) do
        local colon_array = string_api.split(one_msg, ":")
        for _, one_path in ipairs(colon_array) do
            local base_name = file_api.basename(one_path)
            table.insert(ld_lib_tb, {
                ["path"] = one_path,
                ["libname"] = base_name
            })
        end
    end

    local malicious_so_list = cjson.decode(malicious_so_data)

    for _, one_item in pairs(ld_lib_tb) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end

        local find_flag = false
        for _, one_black in pairs(malicious_so_list) do
            if string_api.trim(one_item.libname) == string_api.trim(one_black) then
                find_flag = true
            end
        end
        if find_flag == true then
            table.insert(result, one_item.path)
        end
    end

    return result
end

local function check_ld_env(malicious_so_data)
    local result = {}
    result["files"] = {}
    local ld_env_tb = {"LD_PRELOAD", "LD_AOUT_PRELOAD", "LD_ELF_PRELOAD" }
    local find_flag = false

    for _, env in pairs(ld_env_tb) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end

        local ld_code, ld_msg = agent.exe_shell_cmd("echo $" .. env)
        if ld_code == 0 then
            result[env] = check_so_in_blacklist({ld_msg}, malicious_so_data)
            if #(result[env]) > 0 then
                find_flag = true
                for index, f in ipairs(result[env]) do
                    local file = {}
                    local attr = lfs.attributes(result[env][index])
                    if attr and attr.mode == "file" then
                        file["file_name"] = result[env][index]
                        file["file_md5"] = agent.get_file_md5(result[env][index])
                        file["file_size"] = attr.size
                        table.insert(result["files"], file)
                    end
                end
            end
        else
            agent.error_log("rootkit check(check load so): echo "..env.." fail")
        end
    end

    if find_flag == true then
        return 1, result
    else
        return 0, result
    end
end

local function check_preload_file(malicious_so_data)
    local preload_file = "/etc/ld.so.preload"
    if not file_api.file_exists(preload_file) then
        agent.info_log("[BACK_DIAG]-[check_preload_file]-preload file not exists!")
        return 2, {}
    end

    local preload_content_table = file_api.read_file_content_l(preload_file)
    if not next(preload_content_table) then
        agent.error_log("[BACK_DIAG]-[check_preload_file]-oops, read preload file error!!")
        return 3, {}
    end

    local result = check_so_in_blacklist(preload_content_table, malicious_so_data)
    if #result > 0 then
        return 1, result
    else
        return 0, result
    end
end

local function check_find_cmd_path(cmd_list, path_value)
    local ret = {}
    for k, v in pairs(cmd_list) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end

        for k1, v1 in pairs(path_value) do
            if (start_time + time_out) < os.time() then
                time_out_flag = true
                break
            end

            local attr = lfs.attributes(v1.."/"..v)
            if attr ~= nil and attr.mode == "file" then
                ret[k] = v1.."/"..v
                break
            else
                ret[k] = ""
            end
        end
    end
    return ret
end

local function check_ld_library_path()
    local find_cmd = {}
    local change_flag = false
    local echo_code, echo_msg = agent.exe_shell_cmd("echo $LD_LIBRARY_PATH")
    if echo_code ~= 0 then
        agent.error_log("[BACK_DIAG]-[check_ld_library_path]-oops, echo LD_LIBRARY_PATH error!!")
        return 2, {}
    end

    local cmd_list = {"find", "ls", "strings", "stat", "ps"}
    local path_code, path_value = get_path_env()
    if path_code == false then
        path_value =  {
                        "/sbin",
                        "/bin",
                        "/usr/bin",
                        "/usr/sbin",
                        "/usr/local/bin",
                        "/usr/local/sbin",
                        "/usr/sbin/prelink"
                    }
        agent.error_log("[BACK_DIAG]-[check_ld_library_path]-oops, echo $PATH error, use default!")
    end

    local cmd_path = check_find_cmd_path(cmd_list, path_value)
    -- check the ldd path
    for k, v in pairs(cmd_path) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end

        local err = ""
        local shell_code
        local msg_before_unset
        local msg_after_unset
        local saved_before_unset
        local saved_after_unset
        if v ~= "" then
            shell_code, saved_before_unset, err = agent.exe_shell_cmd("ldd "..v)
            shell_code, msg_before_unset = agent.exe_shell_cmd("ldd "..v.." | sed -e 's/(0x[0-9a-f]*)/0xHEX/' 2>&1")
            shell_code, saved_after_unset, err = agent.exe_shell_cmd("unset LD_LIBRARY_PATH; ldd "..v)
            shell_code, msg_after_unset = agent.exe_shell_cmd("unset LD_LIBRARY_PATH; ldd "..v.."  | sed -e 's/(0x[0-9a-f]*)/0xHEX/' 2>&1")
            if msg_before_unset ~= msg_after_unset and saved_before_unset and saved_after_unset then
                local temp_map = {}
                temp_map.cmd = v
                local final_before_map = {}
                for _, before_v in pairs(saved_before_unset) do
                    local split_before_array = common.split(before_v, "=>")
                    if #split_before_array == 2 then
                        final_before_map[common.trim(split_before_array[1])] = common.trim(split_before_array[2])
                    end
                end
                local final_after_map = {}
                for _, after_v in pairs(saved_after_unset) do
                    local split_after_array = common.split(after_v, "=>")
                    if #split_after_array == 2 then
                        final_after_map[common.trim(split_after_array[1])] = common.trim(split_after_array[2])
                    end
                end
                local final_compare_map = {}
                for after_map_k, after_map_v in pairs(final_after_map) do
                    if final_before_map[after_map_k] == nil then
                        change_flag = true
                        final_compare_map[after_map_k] = "OP_HIDE"
                    elseif final_before_map[after_map_k] ~= final_after_map[after_map_k] then
                        change_flag = true
                        final_compare_map[after_map_k] = "OP_MODIFY"
                    else
                        final_compare_map[after_map_k] = "OP_EQUAL"
                    end
                end
                for before_map_k, before_map_v in pairs(final_before_map) do
                    if final_after_map[before_map_k] == nil then
                        change_flag = true
                        final_compare_map[before_map_k] = "OP_ADD"
                    end
                end
                temp_map.before_unset_output = final_before_map
                temp_map.after_unset_output = final_after_map
                temp_map.before_compare_after = final_compare_map
                table.insert(find_cmd, temp_map)
            end
        end
    end

    if change_flag == true then
        return 1, find_cmd
    else
        return 0, find_cmd
    end
end

local function chk_load_so()
    local result = {}
    result["check_type"] = "chk_load_so"
    result["ret_code"] = 0
    result["ret_msg"] = {}

    local data_code, data_json = agent.get_data_obj_item("script", "data", "agent.collectinfo.linux.rootkit_malicious_so_data", "content", true, true)
    if data_code ~= true then
        --外面的大ret_code，和里面子项的ret_code，是独立的
        result.ret_code = 2
        agent.error_log("[BACK_DIAG]-[chk_load_so]-oops, read data file error!!")
        return result
    end

    local ret_msg_val = {}
    local ld_env_code, ld_env_data = check_ld_env(data_json)
    local preload_code, preload_data = check_preload_file(data_json)
    local library_path_code, library_path_data = check_ld_library_path()
    ret_msg_val["ld_env"] = {}
    ret_msg_val["ld_env"]["ret_code"] = ld_env_code
    ret_msg_val["ld_env"]["ret_msg"] = ld_env_data
    ret_msg_val["preload_file"] = {}
    ret_msg_val["preload_file"]["ret_code"] = preload_code
    ret_msg_val["preload_file"]["ret_msg"] = preload_data
    ret_msg_val["ld_library_path"] = {}
    ret_msg_val["ld_library_path"]["ret_code"] = library_path_code
    ret_msg_val["ld_library_path"]["ret_msg"] = library_path_data
    if ld_env_code == 1 or preload_code == 1 or library_path_code == 1 then
        result["ret_code"] = 1
    end
    result["ret_msg"] = ret_msg_val
    return result
end

------chk_cmd实现------
local function get_cmd_path(path_list, cmd)
    if string.sub(cmd, 1, 1) == '/' then
        local attr = lfs.attributes(cmd)
        if attr ~= nil and attr.mode == "file" then
            return true, cmd
        end
    else
        for k, v in pairs(path_list) do
            local attr = lfs.attributes(v.."/"..cmd)
            if attr ~= nil and attr.mode == "file" then
                return true, v.."/"..cmd
            end
        end
    end
    return false, nil
end


local function chk_command_ok(path_value, command_data)
    local result = {}
    result["not_find_cmd"] = {}
    result["problem_cmd"] = {}
    result["chk_cmd"] = {}
    for _, v in pairs(cjson.decode(command_data)) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end
        local cmd_code, cmd_path = get_cmd_path(path_value, v.cmd)
        if cmd_path ~= nil then
            local get_flag = false
            local one_danger = {}
            local match_rules = {}
            for _, v1 in pairs(v.charater_con) do
                if (start_time + time_out) < os.time() then
                    time_out_flag = true
                    break
                end
                local code, msg = string_cmd.exec("strings -a "..cmd_path.."")
                if code == 0 then
                    local msg1 = rex.match(tostring(msg), v1.rule, 1, "m")
                    if msg1 then
                        get_flag = true
                        match_rules[tostring(v1.id)] = v1.rule
                    end
                end
            end
            if get_flag then
                local file_attributes = lfs.attributes(cmd_path)
                if file_attributes then
                    one_danger["file_name"] = cmd_path
                    one_danger["file_size"] = file_attributes["size"]
                    one_danger["file_owner"] = common.get_user(file_attributes["uid"]) or ""
                    one_danger["file_group"] = common.get_group(file_attributes["gid"]) or ""
                    one_danger["file_permission"] = file_attributes["permissions"]
                    one_danger["access_time"] = file_attributes["access"]
                    one_danger["change_time"] = file_attributes["change"]
                    one_danger["modify_time"] = file_attributes["modification"]
                    one_danger["file_md5"] = agent.get_file_md5(cmd_path) or ""
                    one_danger["file_sha1"] = cryptographic_api.sha1(cmd_path, true) or ""
                    one_danger["file_sha256"] = cryptographic_api.sha256(cmd_path, true) or ""
                    one_danger["match_rules"] = match_rules
                    table.insert(result["problem_cmd"], one_danger)
                end
            end
        else
            table.insert(result["not_find_cmd"], v)
        end
    end
    if #(result["problem_cmd"]) > 0 then
        return 1, result
    else
        return 0, result
    end
end

--[[
 {
    "is_string": false,
    "ret_code": 1,
    "ret_msg": {
        "not_find_cmd": [{
            "cmd": "named",
            "charater_con": [{
                    "id": 63,
                    "rule": "blah"
                },
                {
                    "id": 64,
                    "rule": "bye"
                }
            ]
        }],
        "chk_cmd": [],
        "problem_cmd": [{
            "access_time": 1533611467,
            "match_rules": {
                "153": ".*"
            },
            "modify_time": 1490208765,
            "change_time": 1521101590,
            "file_md5": "69f913f7a2563c41398c63c7e5017ea3",
            "file_size": 31656,
            "file_name": "\/bin\/pwd"
        }]
    },
    "check_type": "chk_cmd"
},
--]]
local function chk_cmd()
    local result = {}
    result["check_type"] = "chk_cmd"
    result["is_string"] = false
    -- get the cmd path env
    local path_code, path_value = get_path_env()
    if path_code == false then
        path_value = {
            "/sbin",
            "/bin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/sbin/prelink"
        }
        agent.error_log("rootkit check(check cmd): get path env fail use default path")
    end

    local data_code, data_json = agent.get_data_obj_item("script", "data", "agent.collectinfo.linux.rootkit_chk_cmd_data", "content", true, true)
    if data_code == false then
        result["ret_code"] = 2
        result["ret_msg"] = {}
        agent.error_log("[BACK_DIAG]-[chk_cmd]-read data file error!")
        return result
    end

    local command_code, command_ret = chk_command_ok(path_value, data_json)
    chk_cmd_ret = command_ret
    result["ret_code"] = command_code
    result["ret_msg"] = command_ret
    return result
end

------chk lack module实现------
local function chk_diff_module()
    -- check the /proc/modules file is exists
    local attr = lfs.attributes("/proc/modules")
    if attr == nil or attr.mode ~= "file" then
        agent.error_log("[BACK_DIAG]-[chk_diff_module]-oops,/proc/modules file not found")
        return 2, {}
    end

    --替换cat命令cat /proc/modules | cut -d' ' -f1 | sort
    -- by binbin.li@qingteng.cn 2017/06/27
    local kernel_modules = file_api.read_file_content_l("/proc/modules")
    local system_module = {}
    for _, line in pairs(kernel_modules) do
        local line_info_t = string_api.split(line)
        if line_info_t and next(line_info_t) and line_info_t[1] then
            table.insert(system_module, line_info_t[1])
        end
    end

    -- get lsmod data
    local cmd_code, cmd_msg, cmd_err = agent.exe_shell_cmd("lsmod | grep -v 'Size *Used *by' | cut -d' ' -f1 | sort")
    if cmd_code ~= 0 then
        agent.error_log("[BACK_DIAG]-[chk_diff_module]-exec lsmod error!")
        return 3, {}
    end

    local lsmod_module = common.split(cmd_msg, "\n")

    -- compare the data
    local result_module = {}
    result_module["lack"] = {}
    result_module["add"] = {}
    local module_flag = {}

    for system_k, system_v in pairs(system_module) do
        for lsmod_k, lsmod_v in pairs(lsmod_module) do
            if system_v == lsmod_v then
                module_flag[system_v] = true
                break
            end
        end
    end

    for _, system_v in pairs(system_module) do
        if module_flag[system_v] == nil then
            --lsmod没有，proc下面有。lsmod相对proc，缺少了
            table.insert(result_module["lack"], system_v)
        end
    end

    for _, lsmod_v in pairs(lsmod_module) do
        if module_flag[lsmod_v] == nil then
            table.insert(result_module["add"], lsmod_v)
        end
    end

    if (#result_module["add"] == 0) and (#result_module["lack"] == 0) then
        return 0, result_module
    else
        return 1, result_module
    end
end

local function chk_lack_module()
    local result = {}
    result["check_type"] = "chk_lack_module"
    local module_code, module_ret = chk_diff_module()
    result["ret_code"] = module_code
    result["ret_msg"] = module_ret
    return result
end

------chk malicious module实现------
local function get_the_lkm_path()
    --替换uname -r命令
    --by binbin.li@qingteng.cn 2017/08/15
    local kernel_ver = ""
    local osinfo = cjson.decode(agent.get_sysinfo())
    if osinfo and type(osinfo) == "table" and next(osinfo) then
        kernel_ver = osinfo.os_info.kernel_ver
    end
    kernel_ver = kernel_ver or ""
    if kernel_ver == "" then
        return 2, "get kernel_ver fail"
    end
    local lkm_path = "/lib/modules/"..kernel_ver
    return 0, lkm_path
end

local function find_system_ker_module(lkm_path)
    local sys_ker_module = {}
    local lkm_code, lkm_msg, lkm_err = agent.popen("find", lkm_path, "-type", "f", "-name", "*.*o")
    if lkm_code ~= 0 then
        agent.error_log("rootkit check(check malicious module): find lkm_path .o fail")
        return false, {}
    end
    local msg_len = string.len(lkm_msg)
    -- check the last c is '\n'
    local c = string.sub(lkm_msg, msg_len, msg_len)
    local is_n = false
    if c == "\n" then
        is_n = true
    end
    while true do
        local i = string.find(lkm_msg, "\n")
        if i ~= nil then
            table.insert(sys_ker_module, string.sub(lkm_msg, 1, i - 1))
            lkm_msg = string.sub(lkm_msg, i + 1)
        elseif i == nil then
            if is_n == false then
                table.insert(sys_ker_module, string.sub(lkm_msg, 1))
            end
            break
        end
    end
    return true, sys_ker_module
end

local function find_malicious_module(malicious_module_data, lkm_path)
    local result = {}
    -- get the system ker module
    local find_ok, sys_module = find_system_ker_module(lkm_path)
    if find_ok == false then
        return -1, {}
    end

    local malicious_module_list = cjson.decode(malicious_module_data)

    for index, one_module in pairs(sys_module) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end

        local malicious_name
        local base_name = file_api.basename(one_module)
        for _, one_malicious in ipairs(malicious_module_list) do
            if base_name == one_malicious then
                malicious_name = one_malicious
                break
            end
        end

        if malicious_name then
            local one_danger = {}
            local file_attributes = lfs.attributes(one_module)
            if file_attributes and file_attributes["mode"] == "file" then
                one_danger["malicious_name"] = malicious_name
                one_danger["file_name"] = one_module
                one_danger["file_size"] = file_attributes["size"]
                one_danger["file_owner"] = common.get_user(file_attributes["uid"]) or ""
                one_danger["file_group"] = common.get_group(file_attributes["gid"]) or ""
                one_danger["file_permission"] = file_attributes["permissions"]
                one_danger["access_time"] = file_attributes["access"]
                one_danger["change_time"] = file_attributes["change"]
                one_danger["modify_time"] = file_attributes["modification"]
                one_danger["file_md5"] = agent.get_file_md5(one_module) or ""
                one_danger["file_sha1"] = cryptographic_api.sha1(one_module, true) or ""
                one_danger["file_sha256"] = cryptographic_api.sha256(one_module, true) or ""
                table.insert(result, one_danger)
            end
        end
    end

    if #result == 0 then
        return 0, result
    else
        return 1, result
    end
end

--[[
{
    "ret_code": 1,
    "ret_msg": [{
        "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
        "malicious_name": "p2.ko",
        "modify_time": 1533614050,
        "change_time": 1533614050,
        "access_time": 1533614050,
        "file_size": 0,
        "file_name": "\/lib\/modules\/2.6.32-696.23.1.el6.x86_64\/misc\/p2.ko"
    }],
    "check_type": "chk_malicious_module"
},
--]]
local function chk_malicious_module()
    local result = {}
    result["check_type"] = "chk_malicious_module"

    -- get the lkm path
    local func_ret, func_msg = get_the_lkm_path()
    if func_ret ~= 0 then
        result["ret_code"] = 2
        result["ret_msg"] = {}
        return result
    end

    -- get the bad so name
    local data_code, data_json = agent.get_data_obj_item("script", "data", "agent.collectinfo.linux.rootkit_malicious_module_data", "content", true, true)
    if data_code == false then
        result["ret_code"] = 3
        result["ret_msg"] = {}
        agent.error_log("[BACK_DIAG]-[chk_malicious_module]-read malicious module data fail")
        return result
    end

    -- find the malicious so
    local find_code, find_ret = find_malicious_module(data_json, func_msg)
    if find_code == 0 or find_code == 1 then
        result["ret_code"] = find_code
    else
        result["ret_code"] = 4
    end
    result["ret_msg"] = find_ret
    return result
end

------chk proc rename实现------
local function chk_proc_cmdline_and_status(chk_proc_wl, proc_list)
    local rename_list = {}
    for _, one_proc in pairs(proc_list) do
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end
        if one_proc.cmd ~= "" then
            local is_rename = false
            if one_proc["is_kernel"] == false and string.sub(one_proc.cmd, 1, 1) == "[" and string.sub(one_proc.cmd, -1, -1) == "]" then
                is_rename = true
                --白名单排除
                for k, v in pairs(chk_proc_wl) do
                    if string.find(v, one_proc.ucmd, 1, true) then
                        is_rename = false
                    end
                end
            end

            if is_rename then
                local exe_path = cmd_api.readlink("/proc/" .. tostring(one_proc.pid) .. "/exe", "f")
                local file_attributes = lfs.attributes(exe_path)
                if exe_path ~= "" and file_attributes then
                    local one_danger = {}
                    one_danger["pid"] = one_proc.pid
                    one_danger["proc_name"] = one_proc["ucmd"]
                    one_danger["fake_name"] = one_proc["cmd"]
                    one_danger["file_name"] = exe_path
                    one_danger["file_size"] = file_attributes["size"]
                    one_danger["file_owner"] = common.get_user(file_attributes["uid"]) or ""
                    one_danger["file_group"] = common.get_group(file_attributes["gid"]) or ""
                    one_danger["file_permission"] = file_attributes["permissions"]
                    one_danger["access_time"] = file_attributes["access"]
                    one_danger["change_time"] = file_attributes["change"]
                    one_danger["modify_time"] = file_attributes["modification"]
                    one_danger["file_md5"] = agent.get_file_md5(exe_path) or ""
                    one_danger["file_sha1"] = cryptographic_api.sha1(exe_path, true) or ""
                    one_danger["file_sha256"] = cryptographic_api.sha256(exe_path, true) or ""
                    table.insert(rename_list, one_danger)
                end
            end
        end
    end

    if #rename_list == 0 then
        return 0, rename_list
    else
        return 1, rename_list
    end
end

--[[
{
    "ret_code": 1,
    "ret_msg": [{
        "proc_name": "hello",
        "pid": 23337,
        "file_name": "\/root\/hello",
        "file_md5": "d4ba6f068a302aaa27e9788d07b8b83f",
        "modify_time": 1533615761,
        "fake_name": "[abc]",
        "access_time": 1533615763,
        "file_size": 8114,
        "change_time": 1533615761
    }],
    "check_type": "chk_proc_rename"
},
--]]
local function chk_proc_rename()
    local result = {}
    result["check_type"] = "chk_proc_rename"

    local data_code, data_json = agent.get_data_obj_item("script", "data", "agent.collectinfo.linux.rootkit_dependable_rename_proc_data", "content", true, true)
    if data_code == false then
        agent.error_log("rootkit check(check proc rename): chk proc rename get data fail")
        result["ret_code"] = 2
        result["ret_msg"] = {}
        return result
    end

    local check_code, check_ret = chk_proc_cmdline_and_status(cjson.decode(data_json), common.get_proc_info())
    result["ret_code"] =  check_code
    result["ret_msg"] = check_ret
    return result
end

------chk_shell_diff实现------
--shell diff只关心被检查的命令是否被修改
--不去关心同一个包的其它命令是否被修改。。
local function remove_uninsterested_files(file_attr_tb, real_file)
    local file_table = {}
    for _, file_attr in ipairs(file_attr_tb) do
        if file_attr["file_name"] == real_file then
            table.insert(file_table, file_attr)
            break
        end
    end
    return file_table
end

local function shell_diff_pkg_chk(real_file)
    local rpm_table = {
        ["package_full_name"] = "",
        ["package_name"] = "",
        ["package_version"] = "",
        ["files"] = {}
    }
    if soft_api.get_rpm_flag() then
        local qf_code, qf_msg = common.execute_shell_l("rpm -qf " .. tostring(real_file))
        if qf_code == 0 and qf_msg then
            rpm_table["package_full_name"] = qf_msg[#qf_msg]
        end
        local ex_qf_code, ex_qf_msg = common.execute_shell_l("rpm -qf " .. tostring(real_file) .. [[ --qf '%{N}\n%{V}\n']])
        if ex_qf_code == 0 and ex_qf_msg then
            rpm_table["package_name"] = ex_qf_msg[#ex_qf_msg - 1]
            rpm_table["package_version"] = ex_qf_msg[#ex_qf_msg]
        end
        local is_reuse_rpm = false
        for _, rpm_pkg in ipairs(chk_rpm_res) do
            if rpm_pkg["package_name"] == rpm_table["package_name"] then
                rpm_table["files"] = remove_uninsterested_files(rpm_pkg["files"], real_file)
                is_reuse_rpm = true
                break
            end
        end
        if not is_reuse_rpm then
            rpm_table["files"] = check_rpm_binary(rpm_table["package_name"], real_file)
        end
    end

    local dpkg_table = {
        ["package_full_name"] = "",
        ["package_name"] = "",
        ["package_version"] = "",
        ["files"] = {}
    }
    if soft_api.get_dpkg_flag() then
        local deb_code, deb_msg = common.execute_shell_l("dpkg -S " .. tostring(real_file))
        if deb_code == 0 and deb_msg then
            local msg_tb = string_api.split(deb_msg[1], ":")
            dpkg_table["package_name"] = msg_tb[1]
        end
        local ex_deb_code, ex_deb_msg = common.execute_shell_l([[dpkg -l ]] .. tostring(dpkg_table["package_name"]) .. [[ | grep "^ii" | awk '{print $2, $3, $4}']])
        if ex_deb_code == 0 and ex_deb_msg then
            local pack_info = string_api.split(ex_deb_msg[1]) --默认以%s+分拆
            dpkg_table["package_full_name"] = tostring(pack_info[1]) .. "_" .. tostring(pack_info[2]) .. "_" .. tostring(pack_info[3])
            dpkg_table["package_name"] = pack_info[1]
            dpkg_table["package_version"] = pack_info[2]
        end
        local is_reuse_dpkg = false
        for _, dpkg_pkg in ipairs(chk_dpkg_res) do
            if dpkg_pkg["package_name"] == dpkg_table["package_name"] then
                dpkg_table["files"] = remove_uninsterested_files(dpkg_pkg["files"], real_file)
                is_reuse_dpkg = true
                break
            end
        end
        if not is_reuse_dpkg then
            dpkg_table["files"] = check_dpkg_binary(dpkg_table["package_name"], real_file)
        end
    end
    if rpm_table["package_name"] == "" and dpkg_table["package_name"] == "" then
        return -1, nil
    elseif #(rpm_table["files"]) == 0 and #(dpkg_table["files"]) == 0 then
        return 0, nil
    else
        if rpm_table["package_name"] == "" then
            rpm_table = {}
        end
        if dpkg_table["package_name"] == "" then
            dpkg_table = {}
        end
        return 1, {
            ["rpm"] = rpm_table,
            ["dpkg"] = dpkg_table
        }
    end
end

local function shell_diff_run_command(cmd_v, args_tb, danger_obj)
    local shell_diff_ret = shell_diff_api.chk_shell_diff({
        {
            ["data_key"] = "cmd_list",
            ["data_value"] = {cmd_v}
        },
        {
            ["data_key"] = "ls_path",
            ["data_value"] = args_tb["ls_path"]
        }
    })
    for _, shell_diff_v in ipairs(shell_diff_ret["ret_msg"]) do
        if shell_diff_v["app_name"] == cmd_v and type(shell_diff_v["ret_msg"]) == "table" and #(shell_diff_v["ret_msg"]) ~= 0 then
            danger_obj["count"] = danger_obj["count"] + 1
            local ret_msg_len = #(shell_diff_v["ret_msg"])
            if ret_msg_len == 1 then
                if shell_diff_v["ret_msg"][1]["local_more"] ~= nil then
                    danger_obj["local_more"] = shell_diff_v["ret_msg"][1]["local_more"]
                end
                if shell_diff_v["ret_msg"][1]["local_less"] ~= nil then
                    danger_obj["local_less"] = shell_diff_v["ret_msg"][1]["local_less"]
                end
            elseif shell_diff_v["app_name"] == "ls" or shell_diff_v["app_name"] == "crontab" then
                --ls要检查多个路径，crontab要检查多个用户
                --所以格式要特殊处理一下
                for _, ls_ret_v in ipairs(shell_diff_v["ret_msg"]) do
                    danger_obj["local_less"][ls_ret_v["ret_type"]] = ls_ret_v["local_less"]
                    danger_obj["local_more"][ls_ret_v["ret_type"]] = ls_ret_v["local_more"]
                end
            end
        end
    end
end

--[[
{
    "ret_code": 0,
    "ret_msg": {
        "not_find_cmd": [],
        "not_package_cmd": [],
        "problem_cmd": [
            {
                "match_rules": [],
                "count": 1,
                "local_less": [],
                "local_more": [],
                "pkg": {
                    "package_name": "coreutils",
                    "files": [
                        {
                            "file_name": "\/usr\/bin\/who",
                            "permissions": "rwxr-xr-x",
                            "modify_time": 1533631480,
                            "access_time": 1533609736,
                            "file_md5": "df3db3f93e1171e65b6d2a6d026261d0",
                            "package_hash": "c2ffdc83d46a651608fdcd96a99cb4606dd61a9c9d94e0522233224aae80aadf",
                            "file_hash": "a89e3c47448051da10f9caeea2982cc4ad9a0de486d4eac6d36835e087996b06",
                            "file_size": 117048,
                            "change_time": 1533631480
                        }
                    ],
                    "package_version": "8.4",
                    "package_full_name": "coreutils-8.4-46.el6.x86_64"
                },
                "cmd": "who"
            }
        ]
    },
    "check_type": "chk_shell_diff"
}
--]]
local function chk_shell_diff(args_tb)
    local result = {}
    result["check_type"] = "chk_shell_diff"
    result["ret_code"] = 0
    result["ret_msg"] = {
        ["not_find_cmd"] = {},--PATH的路径中不存在这个命令
        ["not_package_cmd"] = {}, --不属于任何包的命令，孤魂野鬼
        ["problem_cmd"] = {} --被篡改的命令
    }
    local env_code, env_value = get_path_env()
    if env_code then
        pack_dirs = env_value
    else
        pack_dirs = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
    end
    for _, cmd_v in ipairs(args_tb["cmd"]) do
        local cmd_exist = false
        local cmd_file = ""
        for _, path_v in ipairs(pack_dirs) do
            if file_api.file_exists(path_v .. "/" .. cmd_v) then
                cmd_exist = true
                cmd_file = path_v .. "/" .. cmd_v
                break
            end
        end
        if cmd_exist then
            local real_file = ""
            local read_link_file = cmd_api.readlink(cmd_file, "f")
            if read_link_file ~= "" and read_link_file ~= cmd_file then
                real_file = read_link_file
            else
                real_file = cmd_file
            end
            local pkg_code, pkg_value = shell_diff_pkg_chk(real_file)
            if pkg_code == -1 then
                table.insert(result["ret_msg"]["not_package_cmd"], {["cmd"] = cmd_v, ["path"] = cmd_file})
            elseif pkg_code == 0 then
                --命令没有问题，啥也不做
            else
                --命令被篡改，继续strings匹配和对比运行结果
                local danger_obj = {}
                --虽然同一台机器既有可能装rpm的包，又有可能装dpkg的包
                --但是确定路径下的同一个文件，不可能既属于rpm又属于dpkg
                if next(pkg_value["rpm"]) then
                    danger_obj["pkg"] = pkg_value["rpm"]
                elseif next(pkg_value["dpkg"]) then
                    danger_obj["pkg"] = pkg_value["dpkg"]
                else
                    danger_obj["pkg"] = {}
                end
                danger_obj["cmd"] = cmd_v
                danger_obj["count"] = 1
                danger_obj["match_rules"] = {}
                danger_obj["local_more"] = {}
                danger_obj["local_less"] = {}
                for _, result_v in ipairs(chk_cmd_ret["problem_cmd"]) do
                    if result_v["file_name"] == cmd_file then
                        danger_obj["count"] = danger_obj["count"] + 1
                        danger_obj["match_rules"] = result_v["match_rules"]
                        break
                    end
                end
                shell_diff_run_command(cmd_v, args_tb, danger_obj)
                table.insert(result["ret_msg"]["problem_cmd"], danger_obj)
            end
        else
           table.insert(result["ret_msg"]["not_find_cmd"], cmd_v)
        end
    end
    return result
end

local function rootkit_message()
    local check_handler = {
        ["chk_known_rootkit"] = chk_known_rootkit,
        ["chk_load_so"] = chk_load_so,
        ["chk_cmd"] = chk_cmd,
        ["chk_lack_module"] = chk_lack_module,
        ["chk_malicious_module"] = chk_malicious_module,
        ["chk_proc_rename"] = chk_proc_rename,
        ["chk_shell_diff"] = chk_shell_diff
    }

    local ret_table = {}
    ret_table["ret_code"] = 0
    ret_table["ret_msg"] = {}

    for _, check_obj in ipairs(json_table.args.check_rootkit) do
        local function_handler = check_handler[check_obj["name"]]
        if function_handler ~= nil then
            --[[约定每个check function的返回值都是
            ret_code:0/1,
            ret_msg:{}
            的规范形式
            ]]--
            table.insert(ret_table["ret_msg"], function_handler(check_obj))
        end
        if (start_time + time_out) < os.time() then
            time_out_flag = true
            break
        end
    end

    return ret_table
end
--------通用逻辑相关代码--------
start_time = os.time()
json_table = cjson.decode(json_str)
if json_table["args"]["timeout"] ~= nil then
    time_out = tonumber(json_table["args"]["timeout"])
else
    time_out = 1200
end
local return_message = {}
if json_table["req_id"] ~= nil then
    return_message["req_id"] = json_table["req_id"]
end
return_message["begin_time"] = start_time
return_message["ret_code"] = 0
-- 获取grub版本失败
if json_table["args"]["check_bootkit"] ~= nil then
    return_message["bootkit"] = bootkit_message()
end
if json_table["args"]["package_integrity"] ~= nil then
    return_message["package_integrity"] = package_message()
end
if json_table["args"]["check_rootkit"] ~= nil then
    return_message["rootkit"] = rootkit_message()
end
return_message["time_out_flag"] = time_out_flag
return_message["end_time"] = os.time()
if debug_on then
    agent.lua_print_r(return_message)
else
    report_api.report(0, return_message)
end