texts = { }


function init(args)
    math.randomseed(os.time())
    local file = io.open(args[1], "r");
    for line in file:lines() do
        table.insert(texts, line)
    end
    io.close(file)
end


function request()
    local path = string.format("/%s",texts[math.random(1, #texts)])
    return wrk.format("GET", path, nil, nil)
end