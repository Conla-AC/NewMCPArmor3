# -*- coding: utf-8 -*-
"""Versioned exact NetEase Python import whitelist snapshot."""
from __future__ import absolute_import


RULESET_VERSION = 'netease-python-whitelist-2026-08-01-r2'
SNAPSHOT_DATE = '2026-08-01'
SOURCE_URL = (
    'https://mc.163.com/dev/mcmanual/mc-dev/mcguide/'
    '36-%E5%AE%A1%E6%A0%B8%E4%B8%8E%E4%B8%8B%E6%9E%B6/'
    '%E8%AF%BE%E7%A8%8B07-Python%E6%A8%A1%E5%9D%97%E7%99%BD%E5%90%8D%E5%8D%95.html')
SOURCE_REPOSITORY_URL = (
    'https://github.com/MCNeteaseDevs/netease-bedrock-wiki/blob/main/'
    'mcguide/36-%E5%AE%A1%E6%A0%B8%E4%B8%8E%E4%B8%8B%E6%9E%B6/'
    '%E8%AF%BE%E7%A8%8B07-Python%E6%A8%A1%E5%9D%97%E7%99%BD%E5%90%8D%E5%8D%95.md')
OFFICIAL_MODULE_COUNT = 456


_BASE_MODULES = (
    '__future__', '_md5', '_random',
    'abc', 'ast', 'base64', 'binascii', 'bisect', 'calendar',
    'collections', 'contextlib', 'copy', 'cStringIO', 'datetime',
    'fnmatch', 'functools', 'gzip', 'hashlib', 'heapq', 'io',
    'itertools', 'json', 'keyword', 'logging', 'math', 'mod_log',
    'posixpath', 'Queue', 'random', 're', 'singleton', 'string',
    'struct', 'threading', 'time', 'traceback', 'types', 'uuid',
    'warnings', 'weakref', 'zlib',
    'builtin_modules._inspect', 'builtin_modules._operator',
    'mod.builtin_modules._inspect', 'mod.builtin_modules._operator',
    'mod',
)

_SERVER_COMPONENTS = (
    'achievementCompServer', 'actionCompServer',
    'actorCollidableCompServer', 'actorLootCompServer',
    'actorMotionCompServer', 'actorOwnerCompServer',
    'actorPushableCompServer', 'aiCommandCompServer', 'attrCompServer',
    'auxValueCompServer', 'biomeCompServer', 'blockCompServer',
    'blockEntityExDataCompServer', 'blockInfoCompServer',
    'blockStateCompServer', 'blockUseEventWhiteListCompServer',
    'breathCompServer', 'bulletAttributesCompServer',
    'chatExtensionCompServer', 'chestContainerCompServer',
    'chunkSourceComp', 'collisionBoxCompServer', 'commandCompServer',
    'controlAiCompServer', 'dimensionCompServer', 'effectCompServer',
    'engineCompFactoryServer', 'engineTypeCompServer',
    'entityComponentServer', 'entityDefinitionsCompServer',
    'entityEventCompServer', 'exDataCompServer', 'expCompServer',
    'explosionCompServer', 'featureCompServer', 'flyCompServer',
    'gameCompServer', 'gravityCompServer', 'httpToWebServerCompServer',
    'hurtCompServer', 'interactCompServer', 'itemBannedCompServer',
    'itemCompServer', 'levelCompServer', 'lootCompServer',
    'mobSpawnCompServer', 'modAttrCompServer', 'modelCompServer',
    'moveToCompServer', 'msgCompServer', 'nameCompServer',
    'persistenceCompServer', 'petCompServer', 'playerCompServer',
    'portalCompServer', 'posCompServer', 'projectileCompServer',
    'recipeCompServer', 'redStoneCompServer', 'rideCompServer',
    'rotCompServer', 'scaleCompServer', 'shareableCompServer',
    'tagCompServer', 'tameCompServer', 'timeCompServer',
    'weatherCompServer',
)

_CLIENT_COMPONENTS = (
    'achievementCompClient', 'actionCompClient', 'actorMotionCompClient',
    'actorRenderCompClient', 'attrCompClient', 'audioCustomCompClient',
    'auxValueCompClient', 'biomeCompClient', 'blockCompClient',
    'blockGeometryCompClient', 'blockInfoCompClient',
    'blockUseEventWhiteListCompClient', 'brightnessCompClient',
    'cameraCompClient', 'chunkSourceCompClient', 'collisionBoxCompClient',
    'configCompClient', 'deviceCompClient', 'effectCompClient',
    'engineCompFactoryClient', 'engineEffectBindControlComp',
    'engineTypeCompClient', 'fogCompClient', 'frameAniControlComp',
    'frameAniEntityBindComp', 'frameAniSkeletonBindComp',
    'frameAniTransComp', 'gameCompClient', 'healthCompClient',
    'itemCompClient', 'modAttrCompClient', 'modelCompClient',
    'nameCompClient', 'neteaseShopCompClient', 'operationCompClient',
    'particleControlComp', 'particleEntityBindComp',
    'particleSkeletonBindComp', 'particleSystemCompClient',
    'particleTransComp', 'playerAnimCompClient', 'playerCompClient',
    'playerViewCompClient', 'posCompClient', 'postProcessControlComp',
    'queryVariableCompClient', 'recipeCompClient', 'rideCompClient',
    'rotCompClient', 'skyRenderCompClient', 'tameCompClient',
    'textBoardCompClient', 'textNotifyCompClient', 'timeCompClient',
    'virtualWorldCompClient',
)

_UI_CONTROLS = (
    'baseUIControl', 'buttonUIControl', 'gridUIControl', 'imageUIControl',
    'inputPanelUIControl', 'itemRendererUIControl', 'labelUIControl',
    'minimapUIControl', 'neteaseComboBoxUIControl',
    'neteasePaperDollUIControl', 'progressBarUIControl',
    'scrollViewUIControl', 'selectionWheelUIControl', 'sliderUIControl',
    'stackPanelUIControl', 'switchToggleUIControl',
    'textEditBoxUIControl',
)

_CLIENT_SHARED = (
    '', 'extraClientApi', 'clientEvent', 'ui', 'ui.screenNode',
    'ui.screenController', 'ui.viewBinder', 'ui.viewRequest',
    'ui.NativeScreenManager', 'ui.controls', 'system',
    'system.clientSystem', 'component',
)

_CLIENT_MOD_ONLY = (
    'ui.CustomUIControlProxy', 'ui.CustomUIScreenProxy',
    'ui.miniMapBaseScreen',
)

_SERVER_SHARED = (
    '', 'extraServerApi', 'serverEvent', 'blockEntityData', 'gamePlay',
    'gamePlay.AI', 'gamePlay.AI.customGoal', 'system',
    'system.serverSystem', 'component',
)

_COMMON_SHARED = (
    '', 'mod', 'minecraftEnum', 'EntityType', 'EnchantType', 'ItemType',
    'BiomeType', 'SysSoundType', 'BlockType', 'EffectType',
    'KeyBoardType', 'utils', 'utils.mcmath', 'utils.colorUtil',
    'utils.timer', 'entity', 'entity.entityconst', 'component',
    'component.baseComponent', 'component.blockPaletteComp', 'system',
    'system.baseSystem',
)

_PRESET_MODULES = (
    'Preset', 'Preset.Parts', 'Preset.Parts.WorldPart',
    'Preset.Parts.TriggerPart', 'Preset.Parts.PostprocessPart',
    'Preset.Parts.PortalPart', 'Preset.Parts.PlayerBasicPart',
    'Preset.Parts.EntityBasePart', 'Preset.Parts.CameraTrackPart',
    'Preset.Parts.NavPointsPart', 'Preset.Model', 'Preset.Model.BoxData',
    'Preset.Model.PresetBase', 'Preset.Model.TransformObject',
    'Preset.Model.Transform', 'Preset.Model.SdkInterface',
    'Preset.Model.PartBase', 'Preset.Model.GameObject',
    'Preset.Model.Entity', 'Preset.Model.Entity.EntityPreset',
    'Preset.Model.Entity.EntityObject', 'Preset.Model.Player',
    'Preset.Model.Player.PlayerObject', 'Preset.Model.Player.PlayerPreset',
    'Preset.Model.Block', 'Preset.Model.Block.BlockPreset',
    'Preset.Model.Blueprint',
    'Preset.Model.Blueprint.BaseUIBlueprintScreen',
    'Preset.Model.Blueprint.BaseUIBlueprintPart', 'Preset.Model.Effect',
    'Preset.Model.Effect.EffectObject', 'Preset.Model.Effect.EffectPreset',
    'Preset.Model.Textboard', 'Preset.Model.Textboard.TextboardObject',
    'Preset.Model.Textboard.TextboardPreset', 'Preset.Model.UI',
    'Preset.Model.UI.UIPreset', 'Preset.Controller',
    'Preset.Controller.PresetApi',
)


def _join(prefix, suffix):
    return prefix if not suffix else prefix + '.' + suffix


def _build_official_modules():
    modules = set(_BASE_MODULES)
    for prefix in ('mod.server.component', 'server.component'):
        modules.update(_join(prefix, item) for item in _SERVER_COMPONENTS)
    for prefix in ('mod.client.component', 'client.component'):
        modules.update(_join(prefix, item) for item in _CLIENT_COMPONENTS)
    for prefix in ('mod.client.ui.controls', 'client.ui.controls'):
        modules.update(_join(prefix, item) for item in _UI_CONTROLS)
    modules.update(_join('mod.client', item) for item in _CLIENT_SHARED)
    modules.update(_join('client', item) for item in _CLIENT_SHARED)
    modules.update(_join('mod.client', item) for item in _CLIENT_MOD_ONLY)
    modules.update(_join('mod.server', item) for item in _SERVER_SHARED)
    modules.update(_join('server', item) for item in _SERVER_SHARED)
    modules.update(_join('mod.common', item) for item in _COMMON_SHARED)
    modules.update(_join('common', item) for item in _COMMON_SHARED)
    modules.update(_PRESET_MODULES)
    return frozenset(modules)


OFFICIAL_MODULES = _build_official_modules()
if len(OFFICIAL_MODULES) != OFFICIAL_MODULE_COUNT:
    raise RuntimeError(
        'NetEase whitelist snapshot mismatch: expected %d, got %d' %
        (OFFICIAL_MODULE_COUNT, len(OFFICIAL_MODULES)))


def is_whitelisted_module(module_name):
    return bool(module_name and module_name in OFFICIAL_MODULES)
