# Test Cases for the bof finder

| Chall_name  | Description | Protections| Result |
| ----------- | ----------- |------------|--------|
| bug      | gets overflow  | no canary	|  works  |
| bug1  | overflow in strcpy| no canary	| nope	  |
| bug2  | fulfilling cond to execute system| no canary| nope	  |