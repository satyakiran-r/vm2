'use strict';

// Translate the old options to the new Resolver functionality.
const {
	Resolver,
	DefaultResolver
} = require('./resolver');
const {VMError} = require('./bridge');
const {DefaultFileSystem} = require('./filesystem');
const {makeBuiltinsFromLegacyOptions} = require('./builtin');
const {jsCompiler} = require('./compiler');
const {check} = require('recheck');

/**
 * Require wrapper to be able to annotate require with webpackIgnore.
 *
 * @private
 * @param {string} moduleName - Name of module to load.
 * @return {*} Module exports.
 */
function defaultRequire(moduleName) {
	// Set module.parser.javascript.commonjsMagicComments=true in your webpack config.
	// eslint-disable-next-line global-require
	return require(/* webpackIgnore: true */ moduleName);
}

// source: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_Expressions#Escaping
function escapeRegExp(string) {
	return string.replace(/[.*+\-?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}

function makeExternalMatcherRegex(obj) {
	return escapeRegExp(obj).replace(/\\\\|\//g, '[\\\\/]')
		.replace(/\\\*\\\*/g, '.*').replace(/\\\*/g, '[^\\\\/]*').replace(/\\\?/g, '[^\\\\/]');
}

function validateRegexSafety(regexString) {
	// Validate regex string length to prevent excessive computation
	if (regexString.length > 1000) {
		throw new Error('External module pattern too long');
	}
	
	// Check for potentially dangerous patterns that could cause ReDoS
	const dangerousPatterns = [
		/(\(.+\)\+)+/,        // Multiple nested quantified groups
		/(\(.+\)\*)+/,        // Multiple nested quantified groups
		/(\(.+\)\{[^}]+\})+/, // Multiple nested quantified groups with repetition
		/(\*.*\*)+/,          // Multiple wildcards
		/(\+.*\+)+/,          // Multiple plus quantifiers
	];
	
	for (const pattern of dangerousPatterns) {
		if (pattern.test(regexString)) {
			throw new Error('External module pattern contains potentially unsafe regex patterns');
		}
	}
}

function makeExternalMatcher(obj) {
	const regexString = makeExternalMatcherRegex(obj);
	validateRegexSafety(regexString);

	// Use recheck library to validate regex for ReDoS vulnerabilities
	const fullPattern = `[\\\\/]node_modules[\\\\/]${regexString}(?:[\\\\/](?!(?:.*[\\\\/])?node_modules[\\\\/]).*)?$`;
	const recheckResult = check(fullPattern);
	if (recheckResult.status === 'vulnerable') {
		throw new Error(`External module pattern contains ReDoS vulnerability: ${recheckResult.attack ? recheckResult.attack.pattern : 'potential exponential time complexity'}`);
	}

	return new RegExp(fullPattern);
}

class CustomResolver extends DefaultResolver {

	constructor(fileSystem, globalPaths, builtinModules, rootPaths, pathContext, customResolver, hostRequire, compiler, strict) {
		super(fileSystem, globalPaths, builtinModules);
		this.rootPaths = rootPaths;
		this.pathContext = pathContext;
		this.customResolver = customResolver;
		this.hostRequire = hostRequire;
		this.compiler = compiler;
		this.strict = strict;
	}

	isPathAllowed(filename) {
		return this.rootPaths === undefined || this.rootPaths.some(path => {
			if (!filename.startsWith(path)) return false;
			const len = path.length;
			if (filename.length === len || (len > 0 && this.fs.isSeparator(path[len-1]))) return true;
			return this.fs.isSeparator(filename[len]);
		});
	}

	loadJS(vm, mod, filename) {
		if (this.pathContext(filename, 'js') !== 'host') return super.loadJS(vm, mod, filename);
		const m = this.hostRequire(filename);
		mod.exports = vm.readonly(m);
	}

	loadNode(vm, mod, filename) {
		if (this.pathContext(filename, 'node') !== 'host') return super.loadNode(vm, mod, filename);
		const m = this.hostRequire(filename);
		mod.exports = vm.readonly(m);
	}

	customResolve(x, path, extList) {
		if (this.customResolver === undefined) return undefined;
		const resolved = this.customResolver(x, path);
		if (!resolved) return undefined;
		if (typeof resolved === 'string') {
			return this.loadAsFileOrDirectory(resolved, extList);
		}
		const {module=x, path: resolvedPath} = resolved;
		return this.loadNodeModules(module, [resolvedPath], extList);
	}

	getCompiler(filename) {
		return this.compiler;
	}

	isStrict(filename) {
		return this.strict;
	}

}

class LegacyResolver extends CustomResolver {

	constructor(fileSystem, globalPaths, builtinModules, rootPaths, pathContext, customResolver, hostRequire, compiler, strict, externals, allowTransitive) {
		super(fileSystem, globalPaths, builtinModules, rootPaths, pathContext, customResolver, hostRequire, compiler, strict);
		this.externals = externals.map(makeExternalMatcher);
		this.externalCache = externals.map(pattern => {
			const regexString = makeExternalMatcherRegex(pattern);
			validateRegexSafety(regexString);

			// Use recheck library to validate regex for ReDoS vulnerabilities
			const recheckResult = check(regexString);
			if (recheckResult.status === 'vulnerable') {
				throw new Error(`External module pattern contains ReDoS vulnerability: ${recheckResult.attack ? recheckResult.attack.pattern : 'potential exponential time complexity'}`);
			}

			return new RegExp(regexString);
		});
		this.currMod = undefined;
		this.trustedMods = new WeakMap();
		this.allowTransitive = allowTransitive;
	}

	isPathAllowed(path) {
		return this.isPathAllowedForModule(path, this.currMod);
	}

	isPathAllowedForModule(path, mod) {
		if (!super.isPathAllowed(path)) return false;
		if (mod) {
			if (mod.allowTransitive) return true;
			if (path.startsWith(mod.path)) {
				const rem = path.slice(mod.path.length);
				if (!/(?:^|[\\\\/])node_modules(?:$|[\\\\/])/.test(rem)) return true;
			}
		}
		return this.externals.some(regex => regex.test(path));
	}

	registerModule(mod, filename, path, parent, direct) {
		const trustedParent = this.trustedMods.get(parent);
		this.trustedMods.set(mod, {
			filename,
			path,
			paths: this.genLookupPaths(path),
			allowTransitive: this.allowTransitive &&
				((direct && trustedParent && trustedParent.allowTransitive) || this.externals.some(regex => regex.test(filename)))
		});
	}

	resolveFull(mod, x, options, extList, direct) {
		this.currMod = undefined;
		if (!direct) return super.resolveFull(mod, x, options, extList, false);
		const trustedMod = this.trustedMods.get(mod);
		if (!trustedMod || mod.path !== trustedMod.path) return super.resolveFull(mod, x, options, extList, false);
		const paths = [...mod.paths];
		if (paths.length !== trustedMod.paths.length) return super.resolveFull(mod, x, options, extList, false);
		for (let i = 0; i < paths.length; i++) {
			if (paths[i] !== trustedMod.paths[i]) {
				return super.resolveFull(mod, x, options, extList, false);
			}
		}
		try {
			this.currMod = trustedMod;
			return super.resolveFull(trustedMod, x, options, extList, true);
		} finally {
			this.currMod = undefined;
		}
	}

	checkAccess(mod, filename) {
		const trustedMod = this.trustedMods.get(mod);
		if ((!trustedMod || trustedMod.filename !== filename) && !this.isPathAllowedForModule(filename, undefined)) {
			throw new VMError(`Module '${filename}' is not allowed to be required. The path is outside the border!`, 'EDENIED');
		}
	}

	loadJS(vm, mod, filename) {
		if (this.pathContext(filename, 'js') !== 'host') {
			const trustedMod = this.trustedMods.get(mod);
			const script = this.readScript(filename);
			vm.run(script, {filename, strict: this.isStrict(filename), module: mod, wrapper: 'none', dirname: trustedMod ? trustedMod.path : mod.path});
		} else {
			const m = this.hostRequire(filename);
			mod.exports = vm.readonly(m);
		}
	}

	customResolve(x, path, extList) {
		if (this.customResolver === undefined) return undefined;
		if (!(this.pathIsAbsolute(x) || this.pathIsRelative(x))) {
			if (!this.externalCache.some(regex => regex.test(x))) return undefined;
		}
		const resolved = this.customResolver(x, path);
		if (!resolved) return undefined;
		if (typeof resolved === 'string') {
			const escapedResolved = escapeRegExp(resolved);
			validateRegexSafety(escapedResolved);

			// Use recheck library to validate regex for ReDoS vulnerabilities
			const pattern = '^' + escapedResolved;
			const recheckResult = check(pattern);
			if (recheckResult.status === 'vulnerable') {
				throw new Error(`External module pattern contains ReDoS vulnerability: ${recheckResult.attack ? recheckResult.attack.pattern : 'potential exponential time complexity'}`);
			}

			this.externals.push(new RegExp(pattern));
			return this.loadAsFileOrDirectory(resolved, extList);
		}
		const {module=x, path: resolvedPath} = resolved;
		const escapedResolvedPath = escapeRegExp(resolvedPath);
		validateRegexSafety(escapedResolvedPath);

		// Use recheck library to validate regex for ReDoS vulnerabilities
		const pattern = '^' + escapedResolvedPath;
		const recheckResult = check(pattern);
		if (recheckResult.status === 'vulnerable') {
			throw new Error(`External module pattern contains ReDoS vulnerability: ${recheckResult.attack ? recheckResult.attack.pattern : 'potential exponential time complexity'}`);
		}

		this.externals.push(new RegExp(pattern));
		return this.loadNodeModules(module, [resolvedPath], extList);
	}

}

const DEFAULT_FS = new DefaultFileSystem();

const DENY_RESOLVER = new Resolver(DEFAULT_FS, [], new Map());

function makeResolverFromLegacyOptions(options, override, compiler) {
	if (!options) {
		if (!override) return DENY_RESOLVER;
		const builtins = makeBuiltinsFromLegacyOptions(undefined, defaultRequire, undefined, override);
		return new Resolver(DEFAULT_FS, [], builtins);
	}

	const {
		builtin: builtinOpt,
		mock: mockOpt,
		external: externalOpt,
		root: rootPaths,
		resolve: customResolver,
		customRequire: hostRequire = defaultRequire,
		context = 'host',
		strict = true,
		fs: fsOpt = DEFAULT_FS,
	} = options;

	const builtins = makeBuiltinsFromLegacyOptions(builtinOpt, hostRequire, mockOpt, override);

	if (!externalOpt) return new Resolver(fsOpt, [], builtins);

	if (!compiler) compiler = jsCompiler;

	const checkedRootPaths = rootPaths ? (Array.isArray(rootPaths) ? rootPaths : [rootPaths]).map(f => fsOpt.resolve(f)) : undefined;

	const pathContext = typeof context === 'function' ? context : (() => context);

	if (typeof externalOpt !== 'object') {
		return new CustomResolver(fsOpt, [], builtins, checkedRootPaths, pathContext, customResolver, hostRequire, compiler, strict);
	}

	let transitive = false;
	let external = undefined;
	if (Array.isArray(externalOpt)) {
		external = externalOpt;
	} else {
		external = externalOpt.modules;
		transitive = context !== 'host' && externalOpt.transitive;
	}
	return new LegacyResolver(fsOpt, [], builtins, checkedRootPaths, pathContext, customResolver, hostRequire, compiler, strict, external, transitive);
}

exports.makeResolverFromLegacyOptions = makeResolverFromLegacyOptions;
