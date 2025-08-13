# ASPICE-Function-Evaluate
For ASPICE SWE.3.BP3: Describe dynamic behavior. Evaluate the software detailed design in terms of interoperability, interaction, criticality, technical complexity, risks and testability.

### Interoperability:
Count of the function is called by out of component functions + count the function calls out of component functions.

### Interaction:
Count of the function is called by other functions in the component + count of the function calls other functions in the component.

### Criticality:
Count of different shared resources accessed by the function.


### Cyclomatic Complexity:
According to McCabe's definition, the complexity M is then defined as
M = E - N + 2P

where
E = the number of edges of the graph.
N = the number of nodes of the graph.
P = the number of connected components.

For a single program (or subroutine or method), P always equals 1; a simpler formula for a single subroutine is
M = E − N + 2.

For a structured program with only one entry point and one exit point,
Cyclomatic Complexity is equal to the number of decision points ("if" statements or conditional loops) contained in that program plus one.

i.e., M = Decision Point + 1

Decision points include:
if, for, while, do while, case, default
&&, || (each logical branch counts)
?: ternary operation
goto, catch (optional)
Each case or default counts as a branch

### Testability
The max depth of conditional nesting in a single function.

Depth of conditional nesting refers to the level of nesting within conditional statements (like if, else if, else) in programming code. It indicates how many layers of nested conditional logic a piece of code has.

### Risk
Taking all the above analysis into consideration, the final risk is calculated.

| Risk Level | Interoperability | Interaction | Criticality | Technical Complexity | Testability |
| ---------- | ---------------  | ----------- | ----------- | -------------------- | ----------- |
| High (H) 	 | > 4              | > 6         | > 4         | > 12                 | > 5         |
| Medium (M) | > 4              | > 4         | > 2         | > 5                  | > 3         |
| Low (L)    | -                | -           | -           | -                    | -           |

There are default reference values for risk measurement, but you can adjust them as needed.
Please refer to the following definitions in aspice_swc_analyzer.py and modify them if necessary.

```
"""Risk = High, if all of the properties are larger than the following conditions"""
RISK_H_INTEROPERABILITY
RISK_H_INTERACTION
RISK_H_CRITICALITY
RISK_H_COMPLEXITY
RISK_H_TESTABILITY

"""Risk = Medium, if all of the properties are larger than the following conditions"""
RISK_M_INTEROPERABILITY
RISK_M_INTERACTION
RISK_M_CRITICALITY
RISK_M_COMPLEXITY
RISK_M_TESTABILITY
```

# How to execute this evaluation with example code?

Clone ASPICE evaluation repo
```
git clone git@github.com:FishInBottle/ASPICE-Function-Evaluate.git
```

Update submodule for test
```
cd ASPICE-Function-Evaluate
git submodule update --init --recursive
```

Sparse Checkout (remained CMSIS/Driver only)
```
cd submodule/CMSIS_5
git sparse-checkout init --cone
git sparse-checkout set CMSIS/Driver
```
