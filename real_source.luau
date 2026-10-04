-- real_source.luau
--
-- The second slice of the file, at the level the bytes support. GENERATED, not
-- written: every name and number below was read out of the ciphertext with the
-- key the file's own tag confirms, and nothing was typed in by hand.
--
-- This is DATA, not statements. The statement each step makes is not here,
-- because the opcode is not stored in the instruction: the interpreter rebuilds
-- it per instruction from a table it derives from the key and the block it is
-- in. Lifting that decoder is unfinished work, so no statements are claimed.
--
-- What IS claimed: the key, the function tree, the parameter and step counts,
-- and every name and number each function holds, in its own order.

return {
    key = { 942594296, 1658152469, 1676287984 },
    tag = "cd7d7829287d88c51333c08e4f9116fecce2010ec8a3043d71fc04df06b86238",
    bytes = 10494,
    functions = {
        {
            name = "main",
            parameters = 3,
            steps = 13,
            stack = 658845,
            jumpKey = 1224959151,
            holds = { "game", "Players", "GetService", "PlayerAdded", "Connect" },
        },
        {
            name = "1",
            parameters = 1,
            steps = 56,
            stack = 527469,
            jumpKey = 1188054535,
            holds = { "Character", "Humanoid", "FindFirstChildOfClass", "WalkSpeed", 2, 4, "task", "wait", 3, "Parent" },
        },
        {
            name = "2",
            parameters = 2,
            steps = 6,
            stack = 764925,
            jumpKey = 1370660329,
            holds = { "Chatted", "Connect" },
        },
        {
            name = "2.1",
            parameters = 2,
            steps = 45,
            stack = 601503,
            jumpKey = 1091055403,
            holds = { "lower", "b5c89049c27bb0cc3a5e3b62e506a436cd38155e1b63a640f0d573d889c77235", "[a function, 393 byte(s), checked under salt 'proto:p.2.1e1']" },
        },
    },
    stringTable = {
        [1] = "game",
        [2] = "Players",
        [3] = "GetService",
        [4] = "PlayerAdded",
        [5] = "Connect",
        [6] = "Character",
        [7] = "Humanoid",
        [8] = "FindFirstChildOfClass",
        [9] = "WalkSpeed",
        [10] = "task",
        [11] = "wait",
        [12] = "Parent",
        [13] = "Chatted",
        [14] = "Connect",
        [15] = "lower",
        [16] = "b5c89049c27bb0cc3a5e3b62e506a436cd38155e1b63a640f0d573d889c77235",
    },
    stillShut = {
        note = "function 2.1 holds a packed function of 393 bytes under the"
            .. " salt proto:p.2.1e1. Its key is a string the program computes"
            .. " and compares, and the file keeps only a digest of it, so it"
            .. " cannot be read out of the bytes.",
        digest = "b5c89049c27bb0cc3a5e3b62e506a436cd38155e1b63a640f0d573d889c77235",
    },
}
