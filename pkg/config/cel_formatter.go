// Copyright 2026 The Authors (see AUTHORS file)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/interpreter"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// formatEvalDetails walks the CEL AST and uses the evaluation details to produce
// a human-readable string trace of the evaluation.
func formatEvalDetails(celAst *cel.Ast, details *cel.EvalDetails) string {
	if celAst == nil || details == nil {
		return ""
	}

	state := details.State()
	// Convert to AST using cel-go helpers to avoid deprecated Expr() call
	var expr *exprpb.Expr
	var sourceInfo *exprpb.SourceInfo
	var err error

	// We can use AstToParsedExpr to extract the expression and source info.
	// This works for both checked and unchecked ASTs as we only need the structure.
	var parsed *exprpb.ParsedExpr
	parsed, err = cel.AstToParsedExpr(celAst)
	if err == nil {
		expr = parsed.GetExpr()
		sourceInfo = parsed.GetSourceInfo()
	}

	// If AstToParsedExpr failed or returned nil expr, try AstToCheckedExpr if applicable
	if expr == nil && celAst.IsChecked() {
		var checked *exprpb.CheckedExpr
		checked, err = cel.AstToCheckedExpr(celAst)
		if err == nil {
			expr = checked.GetExpr()
			sourceInfo = checked.GetSourceInfo()
		}
	}

	if err != nil {
		return fmt.Sprintf("failed to convert AST: %v. Raw state: %v", err, state)
	}
	if expr == nil {
		return fmt.Sprintf("failed to extract expression from AST. Raw state: %v", state)
	}

	// ast.ToAST requires CheckedExpr
	checkedExpr := &exprpb.CheckedExpr{
		Expr:       expr,
		SourceInfo: sourceInfo,
	}
	nativeAst, err := ast.ToAST(checkedExpr)
	if err != nil {
		// Fallback if AST conversion fails
		return fmt.Sprintf("failed to convert AST: %v. Raw state: %v", err, state)
	}

	var sb strings.Builder
	writeTrace(&sb, nativeAst.Expr(), state, "", "")
	return sb.String()
}

func writeTrace(sb *strings.Builder, e ast.Expr, state interpreter.EvalState, nodePrefix, childrenPrefix string) {
	if e == nil {
		return
	}

	val, found := state.Value(e.ID())
	valStr := "?"
	if found {
		valStr = fmt.Sprintf("%v", val.Value())
	}

	// Determine status icon
	icon := "[?]"
	if v, ok := val.Value().(bool); ok && found {
		if v {
			icon = "[+]" // Pass
		} else {
			icon = "[x]" // Fail
		}
	} else if found {
		icon = "[v]" // Value present
	}

	var str string
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		fn := call.FunctionName()
		displayFn := basicSymbolMap(fn)
		if displayFn == "" {
			displayFn = fn
		}

		switch fn {
		case "_&&_", "_||_", "!_", "_!_",
			"_==_", "_!=_", "_<_", "_>_", "_<=_", "_>=_":
			str = fmt.Sprintf("%s %s -> %s", icon, displayFn, valStr)
		default:
			str = fmt.Sprintf("%s Call '%s' -> %s", icon, displayFn, valStr)
		}
	case ast.IdentKind:
		name := e.AsIdent()
		str = fmt.Sprintf("%s Ident '%s' -> %s", icon, name, valStr)
	case ast.SelectKind:
		path := resolveSelectPath(e)
		str = fmt.Sprintf("%s Select '%s' -> %s", icon, path, valStr)
	case ast.LiteralKind:
		lit := e.AsLiteral()
		str = fmt.Sprintf("%s Lit '%v' -> %s", icon, lit.Value(), valStr)
	case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.ListKind, ast.MapKind, ast.StructKind:
		str = fmt.Sprintf("%s %v -> %s", icon, e.Kind(), valStr)
	default:
		str = fmt.Sprintf("%s UnknownKind -> %s", icon, valStr)
	}

	fmt.Fprintf(sb, "%s%s\n", nodePrefix, str)

	// Recurse for children
	var children []ast.Expr
	switch e.Kind() {
	case ast.CallKind:
		children = e.AsCall().Args()
	case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.LiteralKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// Other kinds (Ident, Select, Literal, etc.) do not have children we traverse here.
		// Detailed traversal for comprehensions/lists/maps could be added if needed.
	default:
		// Unknown kind - do not traverse
	}

	for i, child := range children {
		isLast := i == len(children)-1
		childNodePrefix := childrenPrefix + "├── "
		childChildrenPrefix := childrenPrefix + "│   "
		if isLast {
			childNodePrefix = childrenPrefix + "└── "
			childChildrenPrefix = childrenPrefix + "    "
		}
		writeTrace(sb, child, state, childNodePrefix, childChildrenPrefix)
	}
}

func resolveSelectPath(e ast.Expr) string {
	if e.Kind() == ast.SelectKind {
		sel := e.AsSelect()
		operandName := resolveSelectPath(sel.Operand())
		if operandName != "" {
			return operandName + "." + sel.FieldName()
		}
	}
	if e.Kind() == ast.IdentKind {
		return e.AsIdent()
	}
	return ""
}

func basicSymbolMap(val string) string {
	switch val {
	case "_&&_":
		return "AND"
	case "_||_":
		return "OR"
	case "!_", "_!_":
		return "NOT"
	case "_==_":
		return "EQUALS"
	case "_!=_":
		return "NOT EQUALS"
	case "_<_":
		return "LESS THAN"
	case "_>_":
		return "GREATER THAN"
	case "_<=_":
		return "LESS THAN OR EQUALS"
	case "_>=_":
		return "GREATER THAN OR EQUALS"
	}
	return ""
}
