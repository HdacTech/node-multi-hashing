{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",

            ],
            "include_dirs": [
                "crypto",
                "<!(node -e \"require('nan')\")"
            ],
            "cflags_cc": [
                "-std=c++0x"
            ],
        }
    ]
}
