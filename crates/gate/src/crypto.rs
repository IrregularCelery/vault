pub mod sha256 {
    use crate::sys::vec::Vec;

    const SHA_256_K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut state: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64) * 8;

        let mut msg = Vec::with_capacity(data.len() + 1 + 8 + 64);

        msg.extend_from_slice(data);
        msg.push(0x80);

        while msg.len() % 64 != 56 {
            msg.push(0x00);
        }

        msg.extend_from_slice(&bit_len.to_be_bytes());

        // Process each 512-bit (64-byte) block
        for block in msg.chunks(64) {
            let mut w = [0u32; 64];

            for i in 0..16 {
                w[i] = u32::from_be_bytes(
                    block[i * 4..i * 4 + 4]
                        .try_into()
                        .expect("SHA-256 block slicing failed: this should never happen"),
                );
            }

            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);

                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }

            // Using standard naming a..h matching the specification equations
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = [
                state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
            ];

            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA_256_K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            state[0] = state[0].wrapping_add(a);
            state[1] = state[1].wrapping_add(b);
            state[2] = state[2].wrapping_add(c);
            state[3] = state[3].wrapping_add(d);
            state[4] = state[4].wrapping_add(e);
            state[5] = state[5].wrapping_add(f);
            state[6] = state[6].wrapping_add(g);
            state[7] = state[7].wrapping_add(h);
        }

        let mut out = [0u8; 32];

        for (i, &word) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }

        out
    }

    #[cfg(test)]
    mod tests {
        use crate::sys::{macros::format, string::String};

        use super::*;

        #[test]
        fn empty_string() {
            let result = hash(b"");

            assert_eq!(
                bytes_to_hex(&result),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn abc() {
            let result = hash(b"abc");

            assert_eq!(
                bytes_to_hex(&result),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn unicode_pi() {
            let result = hash("π".as_bytes());

            assert_eq!(
                bytes_to_hex(&result),
                "2617fcb92baa83a96341de050f07a3186657090881eae6b833f66a035600f35a"
            );
        }

        #[test]
        fn long_sentence() {
            let result = hash(b"The quick brown fox jumps over the lazy dog");

            assert_eq!(
                bytes_to_hex(&result),
                "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
            );
        }

        #[test]
        fn length_55() {
            let data = [b'a'; 55];
            let result = hash(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
            );
        }

        #[test]
        fn length_56() {
            let data = [b'a'; 56];
            let result = hash(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
            );
        }

        #[test]
        fn length_63() {
            let data = [b'a'; 63];
            let result = hash(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"
            );
        }

        #[test]
        fn length_64() {
            let data = [b'a'; 64];
            let result = hash(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
            );
        }

        #[test]
        fn length_65() {
            let data = [b'a'; 65];
            let result = hash(&data);

            assert_eq!(
                bytes_to_hex(&result),
                "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0"
            );
        }

        fn bytes_to_hex(bytes: &[u8; 32]) -> String {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        }
    }
}

pub mod bip39 {
    use crate::{
        crypto::sha256,
        sys::{
            macros::{format, vec},
            random::{self, Rng},
            string::{String, ToString},
            vec::Vec,
        },
    };

    pub fn generate(word_count: usize) -> Result<Vec<String>, &'static str> {
        let entropy_bits = match word_count {
            12 => 128,
            24 => 256,
            _ => return Err("word count must be 12 or 24"),
        };
        let mut entropy = vec![0u8; entropy_bits / 8]; // Divide by 8 for bytes

        random::rng().fill_bytes(&mut entropy);

        entropy_to_mnemonic(&entropy)
    }

    pub fn validate(words: &[&str]) -> Result<(), String> {
        if words.len() != 12 && words.len() != 24 {
            return Err(format!("expected 12 or 24 words, got {}", words.len()));
        }

        let list = wordlist();
        let mut bits: Vec<bool> = Vec::with_capacity(words.len() * 11);

        for word in words {
            let index = list
                .binary_search(word)
                .map_err(|_| format!("unknown word: {}", word))?;

            // Each word encodes 11 bits
            for bit in (0..11).rev() {
                bits.push((index >> bit) & 1 == 1);
            }
        }

        // Total bits = words * 11; Entropy + Checksum bit
        let total = bits.len(); // 132 for 12 words - 264 for 24
        let checksum_len = total / 33; // 4 for 12 words - 8 for 24
        let entropy_len = total - checksum_len;
        let entropy = bits_to_bytes(&bits[..entropy_len]);
        let checksum_bits = sha256_first_bits(&entropy, checksum_len);
        let provided_checksum = &bits[entropy_len..];

        if provided_checksum != checksum_bits.as_slice() {
            return Err("checksum mismatch".to_string());
        }

        Ok(())
    }

    fn wordlist() -> &'static [&'static str] {
        WORDLIST
    }

    fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
        bits.chunks(8)
            .map(|chunk| {
                chunk.iter().enumerate().fold(0u8, |byte, (index, &bit)| {
                    byte | ((bit as u8) << (7 - index))
                })
                // NOTE: Most significant bit first encoding hence the (7 - i)
            })
            .collect()
    }

    fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
        let mut bits = Vec::with_capacity(bytes.len() * 8);

        for &byte in bytes {
            // NOTE: Extract bits Most significant bit first
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1 == 1);
            }
        }

        bits
    }

    fn sha256_first_bits(data: &[u8], count: usize) -> Vec<bool> {
        let hash = sha256::hash(data);
        let bits = bytes_to_bits(&hash);

        bits[..count.min(256)].to_vec()
    }

    fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Vec<String>, &'static str> {
        let entropy_bits = entropy.len() * 8;
        let checksum_bits = entropy_bits / 32;
        let checksum = sha256_first_bits(entropy, checksum_bits);
        let mut bits: Vec<bool> = bytes_to_bits(entropy);

        // Bit stream; Entropy bits + Checksum bits
        bits.extend_from_slice(&checksum);

        let list = wordlist();

        if list.len() != 2048 {
            return Err("bip39 wordlist must have exactly 2048 entries");
        }

        let word_count = bits.len() / 11;
        let mut words = Vec::with_capacity(word_count);

        for i in 0..word_count {
            let mut index = 0usize;

            for bit in 0..11 {
                index = (index << 1) | (bits[i * 11 + bit] as usize);
            }

            words.push(list[index].to_string());
        }

        Ok(words)
    }

    pub const WORDLIST: &[&str; 2048] = &[
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
        "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add",
        "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair",
        "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport",
        "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost",
        "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
        "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
        "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any",
        "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area",
        "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive",
        "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
        "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract",
        "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
        "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby",
        "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana",
        "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle",
        "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave",
        "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
        "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth",
        "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind",
        "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil",
        "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom",
        "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze",
        "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
        "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build",
        "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
        "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
        "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy",
        "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon",
        "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual",
        "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave",
        "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk",
        "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check",
        "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
        "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen",
        "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever",
        "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth",
        "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut",
        "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
        "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
        "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
        "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course",
        "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash",
        "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime",
        "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise",
        "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard",
        "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
        "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
        "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease",
        "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise",
        "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive",
        "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect",
        "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel",
        "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt",
        "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
        "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin",
        "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon",
        "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive",
        "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
        "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
        "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
        "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite",
        "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty",
        "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage",
        "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter",
        "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode",
        "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics",
        "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite",
        "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit",
        "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra",
        "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false",
        "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal",
        "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed",
        "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction",
        "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish",
        "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame",
        "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower",
        "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot",
        "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster",
        "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog",
        "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury",
        "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage",
        "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general",
        "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
        "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide",
        "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold",
        "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain",
        "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery",
        "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym",
        "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh",
        "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog",
        "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint",
        "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home",
        "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour",
        "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle",
        "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore",
        "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose",
        "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate",
        "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial",
        "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect",
        "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite",
        "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar",
        "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey",
        "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen",
        "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit",
        "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label",
        "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin",
        "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf",
        "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend",
        "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
        "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid",
        "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic",
        "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage",
        "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet",
        "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango",
        "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage",
        "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum",
        "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody",
        "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh",
        "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
        "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix",
        "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey",
        "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion",
        "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply",
        "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth",
        "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need",
        "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
        "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal",
        "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear",
        "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe",
        "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office",
        "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion",
        "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit",
        "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich",
        "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner",
        "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda",
        "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party",
        "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
        "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
        "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
        "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer",
        "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play",
        "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole",
        "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
        "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict",
        "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print",
        "priority", "prison", "private", "prize", "problem", "process", "produce", "profit",
        "program", "project", "promote", "proof", "property", "prosper", "protect", "proud",
        "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
        "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid",
        "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit",
        "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp",
        "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor",
        "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record",
        "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular",
        "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
        "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require",
        "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat",
        "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice",
        "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk",
        "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
        "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
        "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe",
        "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy",
        "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene",
        "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen",
        "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section",
        "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense",
        "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
        "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship",
        "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp",
        "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent",
        "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister",
        "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull",
        "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot",
        "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap",
        "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier",
        "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound",
        "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
        "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
        "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
        "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
        "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still",
        "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
        "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject",
        "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit",
        "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface",
        "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp",
        "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol",
        "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank",
        "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten",
        "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then",
        "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb",
        "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired",
        "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet",
        "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top",
        "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward",
        "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap",
        "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger",
        "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth",
        "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve",
        "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable",
        "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform",
        "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update",
        "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used",
        "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley",
        "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet",
        "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran",
        "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin",
        "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void",
        "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut",
        "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way",
        "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
        "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip",
        "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing",
        "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman",
        "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck",
        "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth",
        "zebra", "zero", "zone", "zoo",
    ];
    pub const VECTORS: &[&str; 16] = &[
        // 12-Word
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "cat swing flag economy stadium alone churn speed unique patch report train",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        // 24-Word
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
        "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    ];

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn generate_12_returns_12_words() {
            assert_eq!(generate(12).unwrap().len(), 12);
        }

        #[test]
        fn generate_24_returns_24_words() {
            assert_eq!(generate(24).unwrap().len(), 24);
        }

        #[test]
        fn generate_words_are_all_valid_bip39() {
            let list = wordlist();

            for word in generate(12).unwrap() {
                assert!(list.contains(&word.as_str()), "unknown word: {word}");
            }
        }

        #[test]
        fn roundtrip_12_words() {
            let words = generate(12).unwrap();
            let refs: Vec<&str> = words.iter().map(String::as_str).collect();

            assert!(validate(&refs).is_ok());
        }

        #[test]
        fn roundtrip_24_words() {
            let words = generate(24).unwrap();
            let refs: Vec<&str> = words.iter().map(String::as_str).collect();

            assert!(validate(&refs).is_ok());
        }

        #[test]
        fn validate_rejects_wrong_word_counts() {
            let words = generate(12).unwrap();
            let refs: Vec<&str> = words.iter().map(String::as_str).collect();

            assert!(validate(&[]).is_err());
            assert!(validate(&refs[..1]).is_err());
            assert!(validate(&refs[..11]).is_err());
        }

        #[test]
        fn validate_rejects_unknown_word() {
            let words = generate(12).unwrap();
            let mut refs: Vec<&str> = words.iter().map(String::as_str).collect();

            refs[4] = "poop";

            let err = validate(&refs).unwrap_err();

            assert!(err.contains("poop"));
        }

        #[test]
        fn validate_rejects_bad_checksum() {
            let words = [
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "abandon",
            ];

            assert!(validate(&words).is_err());
        }

        #[test]
        fn validate_rejects_swapped_words() {
            // The swapped version of 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f vector should produce different
            // entropy and should return checksum mismatch
            let valid = [
                "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
                "winner", "thank", "yellow",
            ];
            let swapped = [
                "winner", "legal", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
                "winner", "thank", "yellow",
            ];

            assert!(validate(&valid).is_ok());
            assert!(validate(&swapped).is_err());
        }

        // Known BIP39 vectors (https://github.com/trezor/python-mnemonic/blob/master/vectors.json)

        #[test]
        fn vectors() {
            for vector in VECTORS {
                let words: Vec<&str> = vector.split_whitespace().collect();

                assert!(
                    validate(&words).is_ok(),
                    "validate rejected a known-good mnemonic"
                );
            }
        }

        #[test]
        fn vector_12_all_zeros() {
            assert_vector(
                "00000000000000000000000000000000",
                &[
                    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                    "abandon", "abandon", "abandon", "abandon", "about",
                ],
            );
        }

        #[test]
        fn vector_12_all_ones() {
            assert_vector(
                "ffffffffffffffffffffffffffffffff",
                &[
                    "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo",
                    "wrong",
                ],
            );
        }

        #[test]
        fn vector_12_7f() {
            assert_vector(
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                &[
                    "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful",
                    "legal", "winner", "thank", "yellow",
                ],
            );
        }

        #[test]
        fn vector_12_80() {
            assert_vector(
                "80808080808080808080808080808080",
                &[
                    "letter", "advice", "cage", "absurd", "amount", "doctor", "acoustic", "avoid",
                    "letter", "advice", "cage", "above",
                ],
            );
        }

        #[test]
        fn vector_24_all_zeros() {
            assert_vector(
                "0000000000000000000000000000000000000000000000000000000000000000",
                &[
                    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                    "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                    "abandon", "abandon", "art",
                ],
            );
        }

        #[test]
        fn vector_24_all_ones() {
            assert_vector(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                &[
                    "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo",
                    "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo",
                    "zoo", "vote",
                ],
            );
        }

        fn assert_vector(entropy_hex: &str, expected: &[&str]) {
            let entropy: Vec<u8> = (0..entropy_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&entropy_hex[i..i + 2], 16).unwrap())
                .collect();
            let words = entropy_to_mnemonic(&entropy).unwrap();

            assert_eq!(words, expected, "entropy_to_mnemonic mismatch");

            let refs: Vec<&str> = words.iter().map(String::as_str).collect();

            assert!(
                validate(&refs).is_ok(),
                "validate rejected a known-good mnemonic"
            );
        }
    }
}

pub mod argon2 {
    pub use argon2::Algorithm;
    pub use argon2::Argon2;
    pub use argon2::Params;
    pub use argon2::Version;
}

pub mod ed25519 {
    pub use ed25519_dalek::Signature;
    pub use ed25519_dalek::Signer;
    pub use ed25519_dalek::SigningKey;
    pub use ed25519_dalek::Verifier;
    pub use ed25519_dalek::VerifyingKey;
}

pub mod x25519 {
    pub use x25519_dalek::PublicKey;
    pub use x25519_dalek::StaticSecret;
}

pub mod blake3 {
    pub use blake3::Hasher;
    pub use blake3::derive_key;
    pub use blake3::keyed_hash;
}

pub mod chacha20poly1305 {
    pub use chacha20poly1305::ChaCha20Poly1305;
    pub use chacha20poly1305::Key;
    pub use chacha20poly1305::Nonce;
    pub use chacha20poly1305::aead::Aead;
    pub use chacha20poly1305::aead::AeadCore;
    pub use chacha20poly1305::aead::KeyInit;
    pub use chacha20poly1305::aead::Payload;
}
