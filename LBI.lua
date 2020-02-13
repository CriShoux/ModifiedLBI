local luaOpcodes = {
	{name = "MOVE", type = "ABC"}, {name = "LOADK", type = "ABx"},     
	{name = "LOADBOOL", type = "ABC"}, {name = "LOADNIL", type = "ABC"},
	{name = "GETUPVAL", type = "ABC"}, {name = "GETGLOBAL", type = "ABx"}, 
	{name = "GETTABLE", type = "ABC"}, {name = "SETGLOBAL", type = "ABx"}, 
	{name = "SETUPVAL", type = "ABC"}, {name = "SETTABLE", type = "ABC"},
	{name = "NEWTABLE", type = "ABC"}, {name = "SELF", type = "ABC"},
	{name = "ADD", type = "ABC"}, {name = "SUB", type = "ABC"},
	{name = "MUL", type = "ABC"}, {name = "DIV", type = "ABC"},
	{name = "MOD", type = "ABC"}, {name = "POW", type = "ABC"},
	{name = "UNM", type = "ABC"}, {name = "NOT", type = "ABC"},
	{name = "LEN", type = "ABC"}, {name = "CONCAT", type = "ABC"},
	{name = "JMP", type = "AsBx"}, {name = "EQ", type = "ABC"},
	{name = "LT", type = "ABC"}, {name = "LE", type = "ABC"},
	{name = "TEST", type = "ABC"}, {name = "TESTSET", type = "ABC"},
	{name = "CALL", type = "ABC"}, {name = "TAILCALL", type = "ABC"},
	{name = "RETURN", type = "ABC"}, {name = "FORLOOP", type = "AsBx"},
	{name = "FORPREP", type = "AsBx"}, {name = "TFORLOOP", type = "ABC"},
	{name = "SETLIST", type = "ABC"}, {name = "CLOSE", type = "ABC"},
	{name = "CLOSURE", type = "ABx"}, {name = "VARARG", type = "ABC"}
};

local function getBits(input, n, n2)
	if n2 then
		local total = 0;
		local digitn = 0;
		for i = n, n2 do
			total = total + 2^digitn*getBits(input, i);
			digitn = digitn + 1
		end;
		return total;
	else
		local pn = 2^(n-1);
		return (input % (pn + pn) >= pn) and 1 or 0;
	end;
end;

local function decodeBytecode(bytecode)
	local index = 1;
	local bigEndian = false;
    local intSize;
    local sizeT;

    local getInt, getSizeT;

	local function getInt8()
		local a = bytecode:byte(index, index);
		index = index + 1;
		return a;
	end;
	local function getInt32()
        local a, b, c, d = bytecode:byte(index, index + 3);
        index = index + 4;
        return d*16777216 + c*65536 + b*256 + a;
    end;
    local function getInt64()
        local a = getInt32();
        local b = getInt32();
        return b*4294967296 + a;
    end;
	local function getFloat64()
		local a = getInt32();
		local b = getInt32();
		return (-2*getBits(b, 32)+1)*(2^(getBits(b, 21, 31)-1023))*((getBits(b, 1, 20)*(2^32) + a)/(2^52)+1);
	end;
	local function getString(len)
		local str;
        if len then
            str = bytecode:sub(index, index + len - 1);
            index = index + len;
        else
            len = getSizeT();
            if len == 0 then return; end
            str = bytecode:sub(index, index + len - 1);
            index = index + len;
        end;
        return str;
    end;

	local function decodeChunk()
		local instructions = {};
		local constants = {};
		local prototypes = {};
		local debug = {
			lines = {}
		};

		local chunk = {
			name = getString(),
			firstLine = getInt(),
			lastLine = getInt(),
			upvalues = getInt8(),
			arguments = getInt8(),
			vararg = getInt8(),
			stack = getInt8(),
			instructions = instructions,
			constants = constants,
			prototypes = prototypes,
			debug = debug
		};

        if chunk.name then chunk.name = chunk.name:sub(1, -2); end;
        
		local num;

		-- Decode Instructions
		do
			num = getInt();
			for i = 1, num do
				local instruction = {
					-- opcode
					-- opcode name
					-- type = [ABC, ABx, AsBx]
					-- A, B, C, A Bx, or A sBx
				};

				local data = getInt32();
				local opcode = getBits(data, 1, 6);
				local name = luaOpcodes[opcode + 1].name;
				local type = luaOpcodes[opcode + 1].type;

				instruction.opcode = opcode;
				instruction.name = name;
				instruction.type = type;

				instruction.A = getBits(data, 7, 14);
				if type == "ABC" then
					instruction.B = getBits(data, 24, 32);
					instruction.C = getBits(data, 15, 23);
				elseif type == "ABx" then
					instruction.Bx = getBits(data, 15, 32);
				elseif type == "AsBx" then
					instruction.sBx = getBits(data, 15, 32) - 131071;
				end;

				instructions[i] = instruction;
			end;
		end;

		-- Decode Constants
		do
			num = getInt();
			for i = 1, num do
				local constant = {
					-- type = constant type;
					-- data = constant data;
				};
				local type = getInt8();
				constant.type = type;

				if type == 1 then
					constant.data = (getInt8() ~= 0);
				elseif type == 3 then
					constant.data = getFloat64();
				elseif type == 4 then
					constant.data = getString():sub(1, -2);
				end;

				constants[i-1] = constant;
			end;
		end;

		-- Decode Prototypes
		do
			num = getInt();
			for i = 1, num do
				prototypes[i-1] = decodeChunk();
			end;
		end;

		-- Decode Debug Info
		do
			-- line numbers
			local data = debug.lines;
			num = getInt();
			for i = 1, num do
				data[i] = getInt32();
			end;

			-- locals
			num = getInt();
			for i = 1, num do
				getString():sub(1, -2); -- local name
				getInt32();	-- local start PC
				getInt32();	-- local end PC
			end;

			-- upvalues
			num = getInt();
			for i = 1, num do
				getString(); -- upvalue name
			end;
		end;

		return chunk;
	end;

	-- Verify bytecode header
	do
		assert(getString(4) == "\27Lua", "Lua bytecode expected.");
		assert(getInt8() == 0x51, "Only Lua 5.1 is supported.");
		getInt8();
		bigEndian = (getInt8() == 0);
        intSize = getInt8();
        sizeT = getInt8();

        if intSize == 4 then
            getInt = getInt32;
        elseif intSize == 8 then
            getInt = getInt64;
        else
            error("Unsupported bytecode target platform");
        end;

        if sizeT == 4 then
            getSizeT = getInt32;
        elseif sizeT == 8 then
            getSizeT = getInt64;
        else
            error("Unsupported bytecode target platform");
        end;

        assert(getString(3) == "\4\8\0", "Unsupported bytecode target platform");
	end;

	return decodeChunk();
end;

local function handleReturn(...)
	return select("#", ...), {...};
end;

local function createWrapper(cache, upvalues)
	local instructions = cache.instructions;
	local constants = cache.constants;
	local prototypes = cache.prototypes;

	local stack, top;
	local environment;
	local IP = 1;
	local vararg, varargSize;

	local opcodeFuncs = {
		function(instruction) -- MOVE
			stack[instruction.A] = stack[instruction.B];
		end,
		function(instruction) -- LOADK
			stack[instruction.A] = constants[instruction.Bx].data;
		end,
		function(instruction) -- LOADBOOL
			stack[instruction.A] = instruction.B ~= 0
			if instruction.C ~= 0 then
				IP = IP + 1;
			end;
		end,
		function(instruction) -- LOADNIL
			local stack = stack
			for i = instruction.A, instruction.B do
				stack[i] = nil;
			end;
		end,
		function(instruction) -- GETUPVAL
			stack[instruction.A] = upvalues[instruction.B];
		end,
		function(instruction) -- GETGLOBAL
			local key = constants[instruction.Bx].data;
			stack[instruction.A] = environment[key];
		end,
		function(instruction) -- GETTABLE
			local C = instruction.C;
			local stack = stack;
			C = C > 255 and constants[C-256].data or stack[C];
			stack[instruction.A] = stack[instruction.B][C];
		end,
		function(instruction) -- SETGLOBAL
			local key = constants[instruction.Bx].data;
			environment[key] = stack[instruction.A];
		end,
		function(instruction) -- SETUPVAL
			upvalues[instruction.B] = stack[instruction.A];
		end,
		function(instruction) -- SETTABLE
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A][B] = C
		end,
		function(instruction) -- NEWTABLE
			stack[instruction.A] = {}
		end,
		function(instruction) -- SELF
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack = stack;

			B = stack[B]
			C = C > 255 and constants[C-256].data or stack[C];

			stack[A+1] = B;
			stack[A] = B[C];
		end,
		function(instruction) -- ADD
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B+C;
		end,
		function(instruction) -- SUB
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B - C;
		end,
		function(instruction) -- MUL
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B * C;
		end,
		function(instruction) --DIV
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B / C;
		end,
		function(instruction) -- MOD
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B % C;
		end,
		function(instruction) -- POW
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B ^ C;
		end,
		function(instruction) -- UNM
			stack[instruction.A] = -stack[instruction.B];
		end,
		function(instruction) -- NOT
			stack[instruction.A] = not stack[instruction.B];
		end,
		function(instruction) -- LEN
			stack[instruction.A] = #stack[instruction.B];
		end,
		function(instruction) -- CONCAT
			local B = instruction.B;
			local result = stack[B];
			for i = B+1, instruction.C do
				result = result .. stack[i];
			end;
			stack[instruction.A] = result;
		end,
		function(instruction) -- JUMP
			IP = IP + instruction.sBx;
		end,
		function(instruction) -- EQ
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			A = A ~= 0;
			if (B > 255) then B = constants[B-256].data else B = stack[B]; end;
			if (C > 255) then C = constants[C-256].data else C = stack[C]; end;
			if (B == C) ~= A then
				IP = IP + 1
			end;
		end,
		function(instruction) -- LT
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			A = A ~= 0
			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];
			if (B < C) ~= A then
				IP = IP + 1;
			end;
		end,
		function(instruction) -- LT
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			A = A ~= 0
			B = B > 255 and constants[B-256].data or stack[B]
			C = C > 255 and constants[C-256].data or stack[C]
			if (B <= C) ~= A then
				IP = IP + 1;
			end;
		end,
		function(instruction) -- TEST
			local A = stack[instruction.A];
			if (not not A) == (instruction.C == 0) then
				IP = IP + 1;
			end;
		end,
		function(instruction) -- TESTSET
			local stack = stack;
			local B = stack[instruction.B];

			if (not not B) == (instruction.C == 0) then
				IP = IP + 1;
			else
				stack[instruction.A] = B;
			end;
		end,
		function(instruction) -- CALL
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack = stack;
			local args, results;
			local limit, loop;

			args = {};
			if B ~= 1 then
				if B ~= 0 then
					limit = A+B-1;
				else
					limit = top;
				end;

				loop = 0
				for i = A+1, limit do
					loop = loop + 1;
					args[loop] = stack[i];
				end;

				limit, results = handleReturn(stack[A](unpack(args, 1, limit-A)));
			else
				limit, results = handleReturn(stack[A]());
			end;

			top = A - 1;

			if C ~= 1 then
				if C ~= 0 then
					limit = A+C-2;
				else
					limit = limit+A;
				end;

				loop = 0;
				for i = A, limit do
					loop = loop + 1;
					stack[i] = results[loop];
				end
			end
		end,
		function (instruction) -- TAILCALL
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack = stack;
			local args, results;
			local top, limit, loop = top;

			args = {};
			if B ~= 1 then
				if B ~= 0 then
					limit = A+B-1;
				else
					limit = top;
				end;

				loop = 0;
				for i = A+1, limit do
					loop = loop + 1
					args[#args+1] = stack[i];
				end;

				results = {stack[A](unpack(args, 1, limit-A))};
			else
				results = {stack[A]()};
			end;

			return true, results;
		end,
		function(instruction) -- RETURN
			local A = instruction.A;
			local B = instruction.B;
			local stack = stack;
			local limit;
			local loop, output;

			if B == 1 then
				return true;
			end
			if B == 0 then
				limit = top;
			else
				limit = A + B - 2;
			end;

			output = {};
			local loop = 0
			for i = A, limit do
				loop = loop + 1;
				output[loop] = stack[i];
			end;
			return true, output;
		end,
		function(instruction) -- FORLOOP
			local A = instruction.A;
			local stack = stack;

			local step = stack[A+2];
			local index = stack[A] + step;
			stack[A] = index;

			if step > 0 then
				if index <= stack[A+1] then
					IP = IP + instruction.sBx;
					stack[A+3] = index;
				end;
			else
				if index >= stack[A+1] then
					IP = IP + instruction.sBx;
					stack[A+3] = index;
				end;
			end;
		end,
		function(instruction) -- FORPREP
			local A = instruction.A;
			local stack = stack;

			stack[A] = stack[A] - stack[A+2];
			IP = IP + instruction.sBx;
		end,
		function(instruction) -- TFORLOOP
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack = stack;

			local offset = A+2;
			local result = {stack[A](stack[A+1], stack[A+2])};
			for i = 1, C do
				stack[offset+i] = result[i];
			end;

			if stack[A+3] ~= nil then
				stack[A+2] = stack[A+3];
			else
				IP = IP + 1;
			end;
		end,
		function(instruction) -- SETLIST
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack = stack;

			if C == 0 then
				error("Extended SETLIST");
			else
				local offset = (C - 1) * 50;
				local t = stack[A];

				if B == 0 then
					B = top;
				end;
				for i = 1, B do
					t[offset+i] = stack[A+i];
				end;
			end;
		end,
		function(instruction) -- CLOSE
			io.stderr:flush();
		end,
		 function(instruction) -- CLOSURE
			local proto = prototypes[instruction.Bx];
			local instructions = instructions;
			local stack = stack;

			local indices = {};
			local newUpvals = setmetatable({},
				{
					__index = function(t, k)
						local upval = indices[k];
						return upval.segment[upval.offset];
					end,
					__newindex = function(t, k, v)
						local upval = indices[k];
						upval.segment[upval.offset] = v;
					end
				}
			);
			for i = 1, proto.upvalues do
				local movement = instructions[IP];
				if movement.opcode == 0 then -- MOVE
					indices[i-1] = {segment = stack, offset = movement.B};
				elseif instructions[IP].opcode == 4 then -- GETUPVAL
					indices[i-1] = {segment = upvalues, offset = movement.B};
				end;
				IP = IP + 1
			end;

			local func = createWrapper(proto, newUpvals);
			stack[instruction.A] = func;
		end,
		function(instruction) -- VARARG
			local A = instruction.A;
			local B = instruction.B;
			local stack, vararg = stack, vararg;

			for i = A, A + (B > 0 and B - 1 or varargSize) do
				stack[i] = vararg[i - A];
			end;
		end,
	}

	local function runInstructions()
		local instructions = instructions;
		local instruction, a, b;

		while true do
			instruction = instructions[IP];
			IP = IP + 1;
			a, b = opcodeFuncs[instruction.opcode + 1](instruction);
			if a then
				return b;
			end;
		end;
	end;

	local function func(...)
		local localStack = {};
		local ghostStack = {};

		top = -1
		stack = setmetatable(localStack, {
			__index = ghostStack;
			__newindex = function(t, k, v)
				if k > top and v then
					top = k
				end
				ghostStack[k] = v
			end;
		})
		local args = {...};
		vararg = {}
		varargSize = select("#", ...) - 1;
		for i = 0, varargSize do
			localStack[i] = args[i+1];
			vararg[i] = args[i+1];
		end;

		environment = getfenv();
		IP = 1;
		local a, b = coroutine.resume(coroutine.create(runInstructions));

		if a then
			if b then
				return unpack(b);
			end;
			return;
		else
			local name = cache.name;
			local line = cache.debug.lines[IP];
			local output = (name and name .. ":" or "") .. (line and line .. ":" or "") .. b;
			
			error(output, 0);
		end
	end

	return func;
end

local function interpret(bytecode)
	return createWrapper(decodeBytecode(bytecode));
end;

interpret(string.dump(function()
	local function pr(data)
		print(data);
	end;
	pr("hi");
end))();
