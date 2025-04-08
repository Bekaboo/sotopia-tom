# Sotopia-ToM

## Generate Scenarios

1. Either export openai api key in environment variable `OPENAI_API_KEY` or specify it using the `--openai-api-key`:

    ```sh
    export OPENAI_API_KEY=...
    # or
    ./gen_scenarios.py --openai-api-key <key> [domains ...]
    ```

2. Run

    ```sh
    ./gen_scenarios.py [domains ...]
    ```

    To generate and save scenarios in given domains in `generated/<domain>/`

    e.g.

    ```sh
    ./gen_scenarios.py Legal Education Finance
    ```
