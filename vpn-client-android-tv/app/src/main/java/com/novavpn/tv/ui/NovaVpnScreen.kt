package com.novavpn.tv.ui

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.key.*
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.novavpn.tv.domain.model.ConnectionState

// Цвета NovaVPN
private val NovaBg = Color(0xFF121212)
private val NovaSurface = Color(0xFF1E1E1E)
private val NovaPrimary = Color(0xFF1E88E5)
private val NovaAccent = Color(0xFF00E676)
private val NovaError = Color(0xFFEF5350)
private val NovaYellow = Color(0xFFFFAB40)
private val NovaTextPrimary = Color(0xFFFFFFFF)
private val NovaTextSecondary = Color(0xB3FFFFFF)

/**
 * Главный экран NovaVPN для Android TV.
 * Лаконичный и простой интерфейс, оптимизированный для D-pad навигации.
 */
@Composable
fun NovaVpnScreen(
    uiState: MainUiState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onServerAddrChange: (String) -> Unit,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onToggleSettings: () -> Unit,
    onSaveSettings: () -> Unit,
    onClearError: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(NovaBg),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(48.dp)
        ) {
            // Логотип и название
            Text(
                text = "🛡",
                fontSize = 64.sp,
                modifier = Modifier.padding(bottom = 8.dp)
            )
            Text(
                text = "NovaVPN",
                color = NovaTextPrimary,
                fontSize = 36.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Статус подключения
            StatusDisplay(state = uiState.connectionState)

            Spacer(modifier = Modifier.height(8.dp))

            // Информация о подключении
            if (uiState.connectionState == ConnectionState.CONNECTED) {
                // Статистику можно показать позже
            }

            Spacer(modifier = Modifier.height(32.dp))

            // Кнопка подключения/отключения
            ConnectButton(
                state = uiState.connectionState,
                onConnect = onConnect,
                onDisconnect = onDisconnect
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Кнопка настроек
            TvButton(
                text = if (uiState.showSettings) "Скрыть настройки" else "⚙ Настройки",
                onClick = onToggleSettings,
                backgroundColor = NovaSurface
            )

            // Панель настроек
            AnimatedVisibility(
                visible = uiState.showSettings,
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                SettingsPanel(
                    serverAddr = uiState.serverAddr,
                    email = uiState.email,
                    password = uiState.password,
                    onServerAddrChange = onServerAddrChange,
                    onEmailChange = onEmailChange,
                    onPasswordChange = onPasswordChange,
                    onSave = onSaveSettings
                )
            }

            // Сообщение об ошибке
            uiState.errorMessage?.let { error ->
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = error,
                    color = NovaError,
                    fontSize = 16.sp,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

/**
 * Отображение текущего статуса подключения.
 */
@Composable
fun StatusDisplay(state: ConnectionState) {
    val (color, text) = when (state) {
        ConnectionState.DISCONNECTED -> Pair(NovaError, "Отключён")
        ConnectionState.CONNECTING -> Pair(NovaYellow, "Подключение…")
        ConnectionState.CONNECTED -> Pair(NovaAccent, "Подключён")
        ConnectionState.DISCONNECTING -> Pair(NovaYellow, "Отключение…")
    }

    // Анимация пульсации для connecting
    val animatedAlpha by rememberInfiniteTransition(label = "pulse").animateFloat(
        initialValue = 1f,
        targetValue = 0.4f,
        animationSpec = infiniteRepeatable(
            animation = tween(800),
            repeatMode = RepeatMode.Reverse
        ),
        label = "alpha"
    )

    val displayAlpha = if (state == ConnectionState.CONNECTING || state == ConnectionState.DISCONNECTING) {
        animatedAlpha
    } else {
        1f
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center
    ) {
        // Индикатор
        Box(
            modifier = Modifier
                .size(16.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = displayAlpha))
        )
        Spacer(modifier = Modifier.width(12.dp))
        Text(
            text = text,
            color = color.copy(alpha = displayAlpha),
            fontSize = 24.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

/**
 * Главная кнопка подключения/отключения.
 * Адаптирована для D-pad навигации на Android TV.
 */
@Composable
fun ConnectButton(
    state: ConnectionState,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit
) {
    val isConnected = state == ConnectionState.CONNECTED
    val isTransitioning = state == ConnectionState.CONNECTING || state == ConnectionState.DISCONNECTING

    val buttonText = when (state) {
        ConnectionState.DISCONNECTED -> "Подключиться"
        ConnectionState.CONNECTING -> "Подключение…"
        ConnectionState.CONNECTED -> "Отключиться"
        ConnectionState.DISCONNECTING -> "Отключение…"
    }

    val buttonColor = when (state) {
        ConnectionState.DISCONNECTED -> NovaPrimary
        ConnectionState.CONNECTING -> NovaYellow
        ConnectionState.CONNECTED -> NovaAccent
        ConnectionState.DISCONNECTING -> NovaYellow
    }

    TvButton(
        text = buttonText,
        onClick = {
            when (state) {
                ConnectionState.DISCONNECTED -> onConnect()
                ConnectionState.CONNECTED -> onDisconnect()
                else -> {} // Игнорируем во время переходных состояний
            }
        },
        backgroundColor = buttonColor,
        enabled = !isTransitioning,
        modifier = Modifier
            .width(320.dp)
            .height(64.dp)
    )
}

/**
 * Кнопка, адаптированная для Android TV (D-pad навигация).
 */
@Composable
fun TvButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    backgroundColor: Color = NovaPrimary,
    enabled: Boolean = true
) {
    val focusRequester = remember { FocusRequester() }
    var isFocused by remember { mutableStateOf(false) }

    val bgColor = if (isFocused) backgroundColor.copy(alpha = 1f) else backgroundColor.copy(alpha = 0.7f)
    val borderColor = if (isFocused) NovaTextPrimary else Color.Transparent

    Box(
        modifier = modifier
            .then(Modifier.defaultMinSize(minWidth = 200.dp, minHeight = 48.dp))
            .clip(RoundedCornerShape(12.dp))
            .background(if (enabled) bgColor else bgColor.copy(alpha = 0.4f))
            .border(2.dp, borderColor, RoundedCornerShape(12.dp))
            .focusRequester(focusRequester)
            .onFocusChanged { isFocused = it.isFocused }
            .focusable(enabled)
            .onKeyEvent { event ->
                if (event.type == KeyEventType.KeyUp &&
                    (event.key == Key.Enter || event.key == Key.DirectionCenter)
                ) {
                    if (enabled) onClick()
                    true
                } else false
            },
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = text,
            color = if (enabled) NovaTextPrimary else NovaTextSecondary,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 12.dp)
        )
    }
}

/**
 * Панель настроек подключения.
 */
@Composable
fun SettingsPanel(
    serverAddr: String,
    email: String,
    password: String,
    onServerAddrChange: (String) -> Unit,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onSave: () -> Unit
) {
    Column(
        modifier = Modifier
            .padding(top = 16.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(NovaSurface)
            .padding(24.dp)
            .width(400.dp)
    ) {
        Text(
            text = "Настройки подключения",
            color = NovaTextPrimary,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        TvTextField(
            value = serverAddr,
            onValueChange = onServerAddrChange,
            label = "Сервер (host:port)",
            placeholder = "212.118.43.43:443"
        )

        Spacer(modifier = Modifier.height(12.dp))

        TvTextField(
            value = email,
            onValueChange = onEmailChange,
            label = "Email",
            placeholder = "user@example.com"
        )

        Spacer(modifier = Modifier.height(12.dp))

        TvTextField(
            value = password,
            onValueChange = onPasswordChange,
            label = "Пароль",
            placeholder = "••••••••",
            isPassword = true
        )

        Spacer(modifier = Modifier.height(16.dp))

        TvButton(
            text = "Сохранить",
            onClick = onSave,
            backgroundColor = NovaPrimary,
            modifier = Modifier.fillMaxWidth()
        )
    }
}

/**
 * Текстовое поле, адаптированное для Android TV.
 */
@Composable
fun TvTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    placeholder: String = "",
    isPassword: Boolean = false
) {
    var isFocused by remember { mutableStateOf(false) }

    Column {
        Text(
            text = label,
            color = NovaTextSecondary,
            fontSize = 14.sp,
            modifier = Modifier.padding(bottom = 4.dp)
        )

        BasicTextField(
            value = value,
            onValueChange = onValueChange,
            textStyle = TextStyle(
                color = NovaTextPrimary,
                fontSize = 18.sp
            ),
            cursorBrush = SolidColor(NovaPrimary),
            visualTransformation = if (isPassword) PasswordVisualTransformation() else VisualTransformation.None,
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(NovaBg)
                .border(
                    width = if (isFocused) 2.dp else 1.dp,
                    color = if (isFocused) NovaPrimary else NovaTextSecondary.copy(alpha = 0.3f),
                    shape = RoundedCornerShape(8.dp)
                )
                .onFocusChanged { isFocused = it.isFocused }
                .padding(horizontal = 16.dp, vertical = 14.dp),
            decorationBox = { innerTextField ->
                Box {
                    if (value.isEmpty()) {
                        Text(
                            text = placeholder,
                            color = NovaTextSecondary.copy(alpha = 0.5f),
                            fontSize = 18.sp
                        )
                    }
                    innerTextField()
                }
            }
        )
    }
}
