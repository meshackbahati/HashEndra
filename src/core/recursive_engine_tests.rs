    use super::*;

    #[test]
    fn single_base64_layer_reaches_confident_stop() {
        let engine = RecursiveEngine::new(10);
        let result = engine.explore_paths("SGVsbG8gV29ybGQ=");
        assert_eq!(result.final_result, "Hello World");
        assert!(result.confident_stop);
    }

    #[test]
    fn hex_looking_garbage_is_left_alone() {
        // Regression test: statistical crackers used to "decode" digit-heavy
        // strings into garbage and report success.
        let engine = RecursiveEngine::new(10);
        let result = engine.explore_paths("72368696d696e");
        assert_eq!(result.final_result, "72368696d696e");
        assert_eq!(result.layers_unwrapped, 0);
        assert!(!result.confident_stop);
    }

    #[test]
    fn rot13_flag_unwraps_to_plaintext() {
        let engine = RecursiveEngine::new(10);
        let result = engine.explore_paths("synt{Mx_zr_nyrqvn}");
        assert_eq!(result.final_result, "flag{Zk_me_aledia}");
        assert!(result.confident_stop);
    }

    #[test]
    fn spaced_rot13_decodes_end_to_end() {
        let engine = RecursiveEngine::new(10);
        let result = engine.explore_paths("Gur dhvpx oebja sbk whzcf bire gur ynml qbt");
        assert_eq!(
            result.final_result,
            "The quick brown fox jumps over the lazy dog"
        );
        assert!(result.confident_stop);
    }

    #[test]
    fn plain_english_gains_no_layers() {
        let engine = RecursiveEngine::new(10);
        let result = engine.explore_paths("Hello World, this is plain English text");
        assert_eq!(result.layers_unwrapped, 0);
        assert!(!result.confident_stop);
    }
