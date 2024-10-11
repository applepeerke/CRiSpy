from src.gl.Const import EMPTY


def remove_optional_type_def(type_def) -> str:
    """ Example: return 'myClass' when 'List<myClass>' or Set<myClass<Object>>"""
    if not type_def:
        return EMPTY
    s = type_def.find('<') + 1
    e = type_def.find('<', s)
    e = type_def.find('>', s) if e == -1 else e
    return type_def[s:e] if -1 < s < e else type_def


def get_class_name(line, class_name) -> str:
    if class_name:
        return class_name
    s = line.find(' class ')
    s1 = s + len(' class ')
    e = line.find('{')
    return line[s1:e] if -1 < s < s1 < e else EMPTY


def get_decorator_name(line):
    if not line or not line.startswith('@'):
        return EMPTY
    p = line.find('(')
    key = line[:p] if p > -1 else line
    return key
