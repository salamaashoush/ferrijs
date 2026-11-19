//! `import.meta.url`, `import.meta.filename` and `import.meta.dirname`, as
//! the module that reads them sees them.
//!
//! A bundle is one ES module, so every source file folded into it would
//! read the CHUNK's `import.meta`, whose `url` names no file of the
//! user's. rolldown polyfills these only for CommonJS on Node; for ESM it
//! keeps them as written. Each source file is therefore given its own
//! values before linking, as Node gives each module its own: a file that
//! resolves `new URL('./data.json', import.meta.url)` finds the file next
//! to it.

use std::path::Path;

use oxc::allocator::Allocator;
use oxc::ast::ast::{Expression, Program};
use oxc::ast::builder::AstBuilder;
use oxc::ast_visit::{VisitJsMut, walk_js_mut};
use oxc::span::GetSpan;

/// Replace each `import.meta.url` / `.filename` / `.dirname` in `program`
/// with the value it has for the module at `path`.
pub(crate) fn rewrite<'a>(program: &mut Program<'a>, allocator: &'a Allocator, path: &Path) {
  let Ok(url) = url::Url::from_file_path(path) else {
    return;
  };
  let filename = path.to_string_lossy();
  let dirname = path.parent().map(|dir| dir.to_string_lossy()).unwrap_or_default();
  let mut visitor = Rewrite {
    builder: AstBuilder::new(allocator),
    allocator,
    url: url.as_str(),
    filename: &filename,
    dirname: &dirname,
  };
  visitor.visit_program(program);
}

struct Rewrite<'a, 'v> {
  builder: AstBuilder<'a>,
  allocator: &'a Allocator,
  url: &'v str,
  filename: &'v str,
  dirname: &'v str,
}

impl<'a> VisitJsMut<'a> for Rewrite<'a, '_> {
  fn visit_expression(&mut self, expr: &mut Expression<'a>) {
    let value = expr.as_member_expression().and_then(|member| {
      if !matches!(member.object(), Expression::ImportMeta(_)) {
        return None;
      }
      match member.static_property_name()?.as_str()? {
        "url" => Some(self.url),
        "filename" => Some(self.filename),
        "dirname" => Some(self.dirname),
        _ => None,
      }
    });
    if let Some(value) = value {
      let span = expr.span();
      let value = self.allocator.alloc_str(value);
      *expr = Expression::new_string_literal(span, value, None, &self.builder);
      return;
    }
    walk_js_mut::walk_expression(self, expr);
  }
}
