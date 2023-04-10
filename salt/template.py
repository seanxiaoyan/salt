"""
Manage basic template commands
"""
import codecs
import io
import logging
import os
import time
import salt.utils.data
import salt.utils.files
import salt.utils.sanitizers
import salt.utils.stringio
import salt.utils.versions
log = logging.getLogger(__name__)
SLS_ENCODING = 'utf-8'
SLS_ENCODER = codecs.getencoder(SLS_ENCODING)

def compile_template(template, renderers, default, blacklist, whitelist, saltenv='base', sls='', input_data='', context=None, **kwargs):
    log.info('Trace')
    '\n    Take the path to a template and return the high data structure\n    derived from the template.\n\n    Helpers:\n\n    :param mask_value:\n        Mask value for debugging purposes (prevent sensitive information etc)\n        example: "mask_value="pass*". All "passwd", "password", "pass" will\n        be masked (as text).\n    '
    ret = {}
    log.debug('compile template: %s', template)
    if 'env' in kwargs:
        log.info('Trace')
        kwargs.pop('env')
    if template != ':string:':
        log.info('Trace')
        if not isinstance(template, str):
            log.error('Template was specified incorrectly: %s', template)
            return ret
        if not os.path.isfile(template):
            log.error('Template does not exist: %s', template)
            return ret
        if salt.utils.files.is_empty(template):
            log.debug('Template is an empty file: %s', template)
            return ret
        with codecs.open(template, encoding=SLS_ENCODING) as ifile:
            input_data = ifile.read()
            if not input_data.strip():
                log.error('Template is nothing but whitespace: %s', template)
                return ret
    render_pipe = template_shebang(template, renderers, default, blacklist, whitelist, input_data)
    windows_newline = '\r\n' in input_data
    input_data = io.StringIO(input_data)
    for (render, argline) in render_pipe:
        if salt.utils.stringio.is_readable(input_data):
            input_data.seek(0)
        render_kwargs = dict(renderers=renderers, tmplpath=template)
        if context:
            render_kwargs['context'] = context
        render_kwargs.update(kwargs)
        if argline:
            render_kwargs['argline'] = argline
        start = time.time()
        ret = render(input_data, saltenv, sls, **render_kwargs)
        log.profile("Time (in seconds) to render '%s' using '%s' renderer: %s", template, render.__module__.split('.')[-1], time.time() - start)
        if ret is None:
            time.sleep(0.01)
            ret = render(input_data, saltenv, sls, **render_kwargs)
        input_data = ret
        if log.isEnabledFor(logging.GARBAGE):
            if salt.utils.stringio.is_readable(ret):
                log.debug('Rendered data from file: %s:\n%s', template, salt.utils.sanitizers.mask_args_value(salt.utils.data.decode(ret.read()), kwargs.get('mask_value')))
                ret.seek(0)
    if windows_newline:
        log.info('Trace')
        if salt.utils.stringio.is_readable(ret):
            is_stringio = True
            contents = ret.read()
        else:
            is_stringio = False
            contents = ret
        if isinstance(contents, str):
            if '\r\n' not in contents:
                contents = contents.replace('\n', '\r\n')
                ret = io.StringIO(contents) if is_stringio else contents
            elif is_stringio:
                ret.seek(0)
    return ret

def compile_template_str(template, renderers, default, blacklist, whitelist):
    """
    Take template as a string and return the high data structure
    derived from the template.
    """
    fn_ = salt.utils.files.mkstemp()
    with salt.utils.files.fopen(fn_, 'wb') as ofile:
        ofile.write(SLS_ENCODER(template)[0])
    return compile_template(fn_, renderers, default, blacklist, whitelist)

def template_shebang(template, renderers, default, blacklist, whitelist, input_data):
    """
    Check the template shebang line and return the list of renderers specified
    in the pipe.

    Example shebang lines::

      #!yaml_jinja
      #!yaml_mako
      #!mako|yaml
      #!jinja|yaml
      #!jinja|mako|yaml
      #!mako|yaml|stateconf
      #!jinja|yaml|stateconf
      #!mako|yaml_odict
      #!mako|yaml_odict|stateconf

    """
    line = ''
    if template == ':string:':
        line = input_data.split()[0]
    else:
        with salt.utils.files.fopen(template, 'r') as ifile:
            line = salt.utils.stringutils.to_unicode(ifile.readline())
    if line.startswith('#!') and (not line.startswith('#!/')):
        return check_render_pipe_str(line.strip()[2:], renderers, blacklist, whitelist)
    else:
        return check_render_pipe_str(default, renderers, blacklist, whitelist)
OLD_STYLE_RENDERERS = {}
for comb in ('yaml_jinja', 'yaml_mako', 'yaml_wempy', 'json_jinja', 'json_mako', 'json_wempy', 'yamlex_jinja', 'yamlexyamlex_mako', 'yamlexyamlex_wempy'):
    (fmt, tmpl) = comb.split('_')
    OLD_STYLE_RENDERERS[comb] = '{}|{}'.format(tmpl, fmt)

def check_render_pipe_str(pipestr, renderers, blacklist, whitelist):
    """
    Check that all renderers specified in the pipe string are available.
    If so, return the list of render functions in the pipe as
    (render_func, arg_str) tuples; otherwise return [].
    """
    if pipestr is None:
        return []
    parts = [r.strip() for r in pipestr.split('|')]
    results = []
    try:
        if parts[0] == pipestr and pipestr in OLD_STYLE_RENDERERS:
            parts = OLD_STYLE_RENDERERS[pipestr].split('|')
        for part in parts:
            (name, argline) = (part + ' ').split(' ', 1)
            if whitelist and name not in whitelist or (blacklist and name in blacklist):
                log.warning('The renderer "%s" is disallowed by configuration and will be skipped.', name)
                continue
            results.append((renderers[name], argline.strip()))
        return results
    except KeyError:
        log.error('The renderer "%s" is not available', pipestr)
        return []