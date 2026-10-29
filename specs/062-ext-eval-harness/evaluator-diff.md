# Evaluator copy against its source

`benchmarks/external_eval/injecagent_eval.py` is a reviewed copy of InjecAgent's
`src/output_parsing.py` at commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`, sha256
`b841348cdbc5b87c781bed4a592d375d02d51769ac2435cf2e7e69c08a03937b` (protocol section 1). The
source is evaluator code, not benchmark data. It was fetched once into a scratch folder:

```sh
curl -sfL https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/f19c9f2c79a41046eb13c03c51a24c567a8ffa07/src/output_parsing.py \
  -o output_parsing.py
shasum -a 256 output_parsing.py
```

The script below compares the two files' syntax trees, function by function. It ignores type
annotations, docstrings, comments and formatting, and prints every other difference. It was
run from an empty folder as `python3 -I evaldiff.py output_parsing.py injecagent_eval.py`.

## Result

```text
source sha256 b841348cdbc5b87c781bed4a592d375d02d51769ac2435cf2e7e69c08a03937b
source imports: ['from collections import Counter', 'from nltk import ngrams', 'import re']
functions only in the source: ['evaluate_output_finetuned']
functions only in the copy: ['ngrams', 'prompted_text']
--- output_parser: differs
    @@ -17,4 +17,2 @@
             if key + ':' not in patterns:
    -            print(paragraph)
    -            print(split_text)
                 assert 1 == 0
--- truncate_at_marker: identical
--- detect_overly_long_sequences: identical
--- detect_repetitive_language: identical
--- evaluate_output_prompted: identical
```

So the copy differs from the source only as its docstring states:

- `from nltk import ngrams` is replaced by the stdlib `ngrams` in the copy. The test
  `test_ngrams_is_a_drop_in_for_nltk` checks it.
- The two `print` calls in `output_parser` are dropped (`test_evaluator_signals_a_malformed_output_with_assert`
  checks that nothing is printed).
- `evaluate_output_finetuned` and the `__main__` block are not copied. `prompted_text` is new:
  it repeats source lines 65, 66 and 71.

The four other functions and `evaluate_output_prompted` are identical to the source.

## Script

```python
"""Every AST difference between InjecAgent's output_parsing.py and the harness copy.

Usage: python -I evaldiff.py <source output_parsing.py> <harness injecagent_eval.py>
Annotations, docstrings, comments and formatting are ignored; everything else is compared
statement by statement for each function the copy keeps.
"""

import ast
import difflib
import hashlib
import sys

FUNCS = (
    "output_parser",
    "truncate_at_marker",
    "detect_overly_long_sequences",
    "detect_repetitive_language",
    "evaluate_output_prompted",
)


class Strip(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        node.returns = None
        for a in [*node.args.args, *node.args.kwonlyargs]:
            a.annotation = None
        if node.body and isinstance(node.body[0], ast.Expr) and isinstance(
            getattr(node.body[0], "value", None), ast.Constant
        ) and isinstance(node.body[0].value.value, str):
            node.body = node.body[1:]
        return node

    def visit_AnnAssign(self, node):
        return ast.Assign(targets=[node.target], value=node.value, lineno=node.lineno)


def funcs(path):
    tree = Strip().visit(ast.parse(open(path).read()))
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}, tree


def lines(node):
    return ast.unparse(ast.fix_missing_locations(node)).splitlines()


src_path, copy_path = sys.argv[1:]
print("source sha256", hashlib.sha256(open(src_path, "rb").read()).hexdigest())
src, src_tree = funcs(src_path)
cp, cp_tree = funcs(copy_path)
src_imports = sorted(ast.unparse(n) for n in src_tree.body if isinstance(n, (ast.Import, ast.ImportFrom)))
print("source imports:", src_imports)
print("functions only in the source:", sorted(set(src) - set(cp)))
print("functions only in the copy:", sorted(set(cp) - set(src)))
for name in FUNCS:
    diff = list(difflib.unified_diff(lines(src[name]), lines(cp[name]), "source", "copy", lineterm="", n=1))
    print(f"--- {name}: {'identical' if not diff else 'differs'}")
    for d in diff[2:]:
        print("   ", d)
```
